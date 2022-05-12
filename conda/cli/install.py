# -*- coding: utf-8 -*-
# Copyright (C) 2012 Anaconda, Inc
# SPDX-License-Identifier: BSD-3-Clause
from __future__ import absolute_import, division, print_function, unicode_literals

from logging import getLogger
import json
import os
from os.path import abspath, basename, exists, isdir, isfile, join
from time import perf_counter

from . import common
from .common import check_non_admin
from .. import CondaError
from ..auxlib.ish import dals
from ..base.constants import ROOT_ENV_NAME, DepsModifier, UpdateModifier, REPODATA_FN
from ..base.context import context, locate_prefix_by_name
from ..base.constants import INITIAL_TRUST_ROOT    # Where root.json is currently.
from ..common.compat import scandir, text_type
from ..common.constants import NULL
from ..common.path import paths_equal, is_package_file
from ..core.index import calculate_channel_urls, get_index
from ..core.prefix_data import PrefixData
from ..core.solve import _get_solver_class
from ..exceptions import (CondaExitZero, CondaImportError, CondaOSError, CondaSystemExit,
                          CondaValueError, DirectoryNotACondaEnvironmentError,
                          DirectoryNotFoundError, DryRunExit, EnvironmentLocationNotFound,
                          NoBaseEnvironmentError, PackageNotInstalledError, PackagesNotFoundError,
                          TooManyArgumentsError, UnsatisfiableError,
                          SpecsConfigurationConflictError)
from ..gateways.disk.create import mkdir_p
from ..gateways.disk.delete import delete_trash, path_is_clean
from ..gateways.connection.session import CondaSession  # For trust metadata fetching, at least during development
from ..misc import clone_env, explicit, touch_nonadmin
from ..models.match_spec import MatchSpec
from ..models.enums import MetadataSignatureStatus
from ..plan import revert_actions
from ..resolve import ResolvePackageNotFound

try:
    import conda_content_trust
    from conda_content_trust.common import (
        SignatureError,
        load_metadata_from_file as load_trust_metadata_from_file,
        write_metadata_to_file as write_trust_metadata_to_file,
    )
    from conda_content_trust.authentication import (
        verify_root as verify_trust_root,
        verify_delegation as verify_trust_delegation,
    )
    from conda_content_trust.signing import wrap_as_signable
except ImportError:
    conda_content_trust = None


log = getLogger(__name__)
stderrlog = getLogger('conda.stderr')


def check_prefix(prefix, json=False):
    name = basename(prefix)
    error = None
    if name == ROOT_ENV_NAME:
        error = "'%s' is a reserved environment name" % name
    if exists(prefix):
        if isdir(prefix) and 'conda-meta' not in tuple(entry.name for entry in scandir(prefix)):
            return None
        error = "prefix already exists: %s" % prefix

    if error:
        raise CondaValueError(error, json)

    if ' ' in prefix:
        stderrlog.warning("WARNING: A space was detected in your requested environment path\n"
                          "'%s'\n"
                          "Spaces in paths can sometimes be problematic." % prefix)


def clone(src_arg, dst_prefix, json=False, quiet=False, index_args=None):
    if os.sep in src_arg:
        src_prefix = abspath(src_arg)
        if not isdir(src_prefix):
            raise DirectoryNotFoundError(src_arg)
    else:
        assert context._argparse_args.clone is not None
        src_prefix = locate_prefix_by_name(context._argparse_args.clone)

    if not json:
        print("Source:      %s" % src_prefix)
        print("Destination: %s" % dst_prefix)

    actions, untracked_files = clone_env(src_prefix, dst_prefix,
                                         verbose=not json,
                                         quiet=quiet,
                                         index_args=index_args)

    if json:
        common.stdout_json_success(
            actions=actions,
            untracked_files=list(untracked_files),
            src_prefix=src_prefix,
            dst_prefix=dst_prefix
        )


def print_activate(env_name_or_prefix):  # pragma: no cover
    if not context.quiet and not context.json:
        message = dals("""
        #
        # To activate this environment, use
        #
        #     $ conda activate %s
        #
        # To deactivate an active environment, use
        #
        #     $ conda deactivate
        """) % env_name_or_prefix
        print(message)  # TODO: use logger


def get_revision(arg, json=False):
    try:
        return int(arg)
    except ValueError:
        raise CondaValueError("expected revision number, not: '%s'" % arg, json)


def install(args, parser, command='install'):
    """
    conda install, conda update, and conda create
    """
    context.validate_configuration()
    check_non_admin()
    # this is sort of a hack.  current_repodata.json may not have any .tar.bz2 files,
    #    because it deduplicates records that exist as both formats.  Forcing this to
    #    repodata.json ensures that .tar.bz2 files are available
    if context.use_only_tar_bz2:
        args.repodata_fns = ('repodata.json', )

    newenv = bool(command == 'create')
    isupdate = bool(command == 'update')
    isinstall = bool(command == 'install')
    isremove = bool(command == 'remove')
    if newenv:
        common.ensure_name_or_prefix(args, command)
    prefix = context.target_prefix
    if newenv:
        check_prefix(prefix, json=context.json)
    if context.force_32bit and prefix == context.root_prefix:
        raise CondaValueError("cannot use CONDA_FORCE_32BIT=1 in base env")
    if isupdate and not (args.file or args.packages
                         or context.update_modifier == UpdateModifier.UPDATE_ALL):
        raise CondaValueError("""no package names supplied
# Example: conda update -n myenv scipy
""")

    if not newenv:
        if isdir(prefix):
            delete_trash(prefix)
            if not isfile(join(prefix, 'conda-meta', 'history')):
                if paths_equal(prefix, context.conda_prefix):
                    raise NoBaseEnvironmentError()
                else:
                    if not path_is_clean(prefix):
                        raise DirectoryNotACondaEnvironmentError(prefix)
            else:
                # fall-through expected under normal operation
                pass
        else:
            if hasattr(args, "mkdir") and args.mkdir:
                try:
                    mkdir_p(prefix)
                except EnvironmentError as e:
                    raise CondaOSError("Could not create directory: %s" % prefix, caused_by=e)
            else:
                raise EnvironmentLocationNotFound(prefix)

    args_packages = [s.strip('"\'') for s in args.packages]
    if newenv and not args.no_default_packages:
        # Override defaults if they are specified at the command line
        # TODO: rework in 4.4 branch using MatchSpec
        args_packages_names = [pkg.replace(' ', '=').split('=', 1)[0] for pkg in args_packages]
        for default_pkg in context.create_default_packages:
            default_pkg_name = default_pkg.replace(' ', '=').split('=', 1)[0]
            if default_pkg_name not in args_packages_names:
                args_packages.append(default_pkg)

    index_args = {
        'use_cache': args.use_index_cache,
        'channel_urls': context.channels,
        'unknown': args.unknown,
        'prepend': not args.override_channels,
        'use_local': args.use_local
    }

    num_cp = sum(is_package_file(s) for s in args_packages)
    if num_cp:
        if num_cp == len(args_packages):
            explicit(args_packages, prefix, verbose=not context.quiet)
            return
        else:
            raise CondaValueError("cannot mix specifications with conda package"
                                  " filenames")

    specs = []
    if args.file:
        for fpath in args.file:
            try:
                specs.extend(common.specs_from_url(fpath, json=context.json))
            except UnicodeError:
                raise CondaError("Error reading file, file should be a text file containing"
                                 " packages \nconda create --help for details")
        if '@EXPLICIT' in specs:
            explicit(specs, prefix, verbose=not context.quiet, index_args=index_args)
            return
    specs.extend(common.specs_from_args(args_packages, json=context.json))

    if isinstall and args.revision:
        get_revision(args.revision, json=context.json)
    elif isinstall and not (args.file or args_packages):
        raise CondaValueError("too few arguments, "
                              "must supply command line package specs or --file")

    # for 'conda update', make sure the requested specs actually exist in the prefix
    # and that they are name-only specs
    if isupdate and context.update_modifier != UpdateModifier.UPDATE_ALL:
        prefix_data = PrefixData(prefix)
        for spec in specs:
            spec = MatchSpec(spec)
            if not spec.is_name_only_spec:
                raise CondaError("Invalid spec for 'conda update': %s\n"
                                 "Use 'conda install' instead." % spec)
            if not prefix_data.get(spec.name, None):
                raise PackageNotInstalledError(prefix, spec.name)

    if newenv and args.clone:
        if args.packages:
            raise TooManyArgumentsError(0, len(args.packages), list(args.packages),
                                        'did not expect any arguments for --clone')

        clone(args.clone, prefix, json=context.json, quiet=context.quiet, index_args=index_args)
        touch_nonadmin(prefix)
        print_activate(args.name if args.name else prefix)
        return

    repodata_fns = args.repodata_fns
    if not repodata_fns:
        repodata_fns = context.repodata_fns
    if REPODATA_FN not in repodata_fns:
        repodata_fns.append(REPODATA_FN)

    args_set_update_modifier = hasattr(args, "update_modifier") and args.update_modifier != NULL
    # This helps us differentiate between an update, the --freeze-installed option, and the retry
    # behavior in our initial fast frozen solve
    _should_retry_unfrozen = (not args_set_update_modifier or args.update_modifier not in (
        UpdateModifier.FREEZE_INSTALLED,
        UpdateModifier.UPDATE_SPECS)) and not newenv

    for repodata_fn in repodata_fns:
        try:
            if isinstall and args.revision:
                index = get_index(channel_urls=index_args['channel_urls'],
                                  prepend=index_args['prepend'], platform=None,
                                  use_local=index_args['use_local'],
                                  use_cache=index_args['use_cache'],
                                  unknown=index_args['unknown'], prefix=prefix,
                                  repodata_fn=repodata_fn)
                unlink_link_transaction = revert_actions(prefix, get_revision(args.revision),
                                                         index)
            else:
                SolverType = _get_solver_class()
                solver = SolverType(prefix, context.channels, context.subdirs, specs_to_add=specs,
                                    repodata_fn=repodata_fn, command=args.cmd)
                update_modifier = context.update_modifier
                if (isinstall or isremove) and args.update_modifier == NULL:
                    update_modifier = UpdateModifier.FREEZE_INSTALLED
                deps_modifier = context.deps_modifier
                if isupdate:
                    deps_modifier = context.deps_modifier or DepsModifier.UPDATE_SPECS

                unlink_link_transaction = solver.solve_for_transaction(
                    deps_modifier=deps_modifier,
                    update_modifier=update_modifier,
                    force_reinstall=context.force_reinstall or context.force,
                    should_retry_solve=(_should_retry_unfrozen or repodata_fn != repodata_fns[-1]),
                )
            # we only need one of these to work.  If we haven't raised an exception,
            #   we're good.
            break

        except (ResolvePackageNotFound, PackagesNotFoundError) as e:
            # end of the line.  Raise the exception
            if repodata_fn == repodata_fns[-1]:
                # PackagesNotFoundError is the only exception type we want to raise.
                #    Over time, we should try to get rid of ResolvePackageNotFound
                if isinstance(e, PackagesNotFoundError):
                    raise e
                else:
                    channels_urls = tuple(calculate_channel_urls(
                        channel_urls=index_args['channel_urls'],
                        prepend=index_args['prepend'],
                        platform=None,
                        use_local=index_args['use_local'],
                    ))
                    # convert the ResolvePackageNotFound into PackagesNotFoundError
                    raise PackagesNotFoundError(e._formatted_chains, channels_urls)

        except (UnsatisfiableError, SystemExit, SpecsConfigurationConflictError) as e:
            # Quick solve with frozen env or trimmed repodata failed.  Try again without that.
            if not hasattr(args, 'update_modifier'):
                if repodata_fn == repodata_fns[-1]:
                    raise e
            elif _should_retry_unfrozen:
                try:
                    unlink_link_transaction = solver.solve_for_transaction(
                        deps_modifier=deps_modifier,
                        update_modifier=UpdateModifier.UPDATE_SPECS,
                        force_reinstall=context.force_reinstall or context.force,
                        should_retry_solve=(repodata_fn != repodata_fns[-1]),
                    )
                except (UnsatisfiableError, SystemExit, SpecsConfigurationConflictError) as e:
                    # Unsatisfiable package specifications/no such revision/import error
                    if e.args and 'could not import' in e.args[0]:
                        raise CondaImportError(text_type(e))
                    # we want to fall through without raising if we're not at the end of the list
                    #    of fns.  That way, we fall to the next fn.
                    if repodata_fn == repodata_fns[-1]:
                        raise e
            elif repodata_fn != repodata_fns[-1]:
                continue  # if we hit this, we should retry with next repodata source
            else:
                # end of the line.  Raise the exception
                # Unsatisfiable package specifications/no such revision/import error
                if e.args and 'could not import' in e.args[0]:
                    raise CondaImportError(text_type(e))
                raise e
    # # Verify
    # if context.extra_safety_checks:
    #     if conda_content_trust is None:
    #         log.warn("metadata signature verification requested, "
    #                  "but `conda-content-trust` is not installed.")
    #     elif not context.signing_metadata_url_base:
    #         log.info("metadata signature verification requested, "
    #                  "but no metadata URL base has been specified.")
    #     else:
    #         t_before_trust_refresh = perf_counter()
    #         refresh_signing_metadata()  # -->  conda.trust.refresh_trust_metadata
    #         t_after_trust_refresh = perf_counter()
    #         # TODO: Downgrade from info to debug. <~>
    #         log.info('Trust metadata refresh complete.  Total time consumed: ' + str(t_before_trust_refresh - t_after_trust_refresh))

    # Determine which PackageRecords are involved in this transaction.
    # **Assuming that these map to P

    ENV_PREFIX = '/home/s/conda/devenv/Linux/envs/devenv-3.8-c'    # debug

    # names_of_pkgs = [prec.name for prec in unlink_link_transaction.prefix_setups[ENV_PREFIX].link_precs]

    # Testing

    # TODO (AV): Pull contents of this conditional into a separate module/function
    if context.extra_safety_checks:
        if conda_content_trust is None:
            log.warn("metadata signature verification requested, "
                     "but `conda-content-trust` is not installed.")
        elif not context.signing_metadata_url_base:
            log.info("metadata signature verification requested, "
                     "but no metadata URL base has been specified.")
        else:
            t_before_trust_refresh = perf_counter()
            _refresh_signing_metadata()
            t_after_trust_refresh = perf_counter()
            # TODO: Downgrade from info to debug. <~>
            log.info('Trust metadata refresh complete.  Total time consumed: ' + str(round(t_after_trust_refresh - t_before_trust_refresh, 3)) + 's.')

    for prec in unlink_link_transaction.prefix_setups[ENV_PREFIX].link_precs:
        if signatures in prec and prec['signatures']:
            print(prec['signatures'])
            signable = wrap_as_signable(info)

        for signature_entry in prec['signatures']

        prec['metadata_signature_status'] = MetadataSignatureStatus.error#verified

    handle_txn(unlink_link_transaction, prefix, args, newenv)


def handle_txn(unlink_link_transaction, prefix, args, newenv, remove_op=False):
    if unlink_link_transaction.nothing_to_do:
        if remove_op:
            # No packages found to remove from environment
            raise PackagesNotFoundError(args.package_names)
        elif not newenv:
            if context.json:
                common.stdout_json_success(message='All requested packages already installed.')
            else:
                print('\n# All requested packages already installed.\n')
            return

    if not context.json:
        unlink_link_transaction.print_transaction_summary()
        common.confirm_yn()

    elif context.dry_run:
        actions = unlink_link_transaction._make_legacy_action_groups()[0]
        common.stdout_json_success(prefix=prefix, actions=actions, dry_run=True)
        raise DryRunExit()

    try:
        unlink_link_transaction.download_and_extract()
        if context.download_only:
            raise CondaExitZero('Package caches prepared. UnlinkLinkTransaction cancelled with '
                                '--download-only option.')
        unlink_link_transaction.execute()

    except SystemExit as e:
        raise CondaSystemExit('Exiting', e)

    if newenv:
        touch_nonadmin(prefix)
        print_activate(args.name if args.name else prefix)

    if context.json:
        actions = unlink_link_transaction._make_legacy_action_groups()[0]
        common.stdout_json_success(prefix=prefix, actions=actions)



# TODO: These refresh functions should go into their own module
#       (or at least not be in this one).

def _refresh_signing_metadata():
    if not isdir(context.av_data_dir):
        log.info("creating directory for artifact verification metadata")
        makedirs(context.av_data_dir)
    root_trust_metadata = _refresh_signing_root()
    key_mgr_trust_metadata = _refresh_signing_keymgr(root_trust_metadata)

def _refresh_signing_root():
    # TODO (AV): formalize paths for `*.root.json` and `key_mgr.json` on server-side
    trusted_root = INITIAL_TRUST_ROOT

    # Load current trust root metadata from filesystem
    latest_root_id, latest_root_path = -1, None
    for cur_path in iglob(join(context.av_data_dir, "[0-9]*.root.json")):
        # TODO (AV): better pattern matching in above glob
        cur_id = basename(cur_path).split(".")[0]
        if cur_id.isdigit():
            cur_id = int(cur_id)
            if cur_id > latest_root_id:
                latest_root_id, latest_root_path = cur_id, cur_path

    if latest_root_path is None:
        log.debug(f"No root metadata in {context.av_data_dir}. "
                  "Using built-in root metadata.")
    else:
        log.info(f"Loading root metadata from {latest_root_path}.")
        trusted_root = load_trust_metadata_from_file(latest_root_path)

    # Refresh trust root metadata
    attempt_refresh = True
    while attempt_refresh:
        # TODO (AV): caching mechanism to reduce number of refresh requests
        next_version_of_root = 1 + trusted_root['signed']['version']
        next_root_fname = str(next_version_of_root) + '.root.json'
        next_root_path = join(context.av_data_dir, next_root_fname)
        try:
            update_url = f"{channel.base_url}/{next_root_fname}"    # Find a sensible source for
            log.info(f"Fetching updated trust root if it exists: {update_url}")

            # TODO (AV): support fetching root data with credentials
            untrusted_root = fetch_channel_signing_data(
                    context.signing_metadata_url_base,
                    next_root_fname)

            verify_trust_root(trusted_root, untrusted_root)

            # New trust root metadata checks out
            trusted_root = untrusted_root
            write_trust_metadata_to_file(trusted_root, next_root_path)

        # TODO (AV): more error handling improvements (?)
        except (HTTPError,) as err:
            # HTTP 404 implies no updated root.json is available, which is
            # not really an "error" and does not need to be logged.
            if err.response.status_code not in (404,):
                log.error(err)
            attempt_refresh = False
        except Exception as err:
            log.error(err)
            attempt_refresh = False

def _refresh_signing_keymgr(trusted_root):
    # Refresh key manager metadata
    key_mgr_filename = "key_mgr.json"  # TODO (AV): make this a constant or config value
    key_mgr = None

    key_mgr_path = join(context.av_data_dir, key_mgr_filename)
    try:
        untrusted_key_mgr = fetch_channel_signing_data(
                context.signing_metadata_url_base,
                key_mgr_filename)
        verify_trust_delegation("key_mgr", untrusted_key_mgr, trusted_root)
        key_mgr = untrusted_key_mgr
        write_trust_metadata_to_file(key_mgr, key_mgr_path)
    except (ConnectionError, HTTPError,) as err:
        log.warn(f"Could not retrieve {channel.base_url}/{key_mgr_filename}: {err}")
    # TODO (AV): much more sensible error handling here
    except Exception as err:
        log.error(err)

    # If key_mgr is unavailable from server, fall back to copy on disk
    if key_mgr is None and exists(key_mgr_path):
        key_mgr = load_trust_metadata_from_file(key_mgr_path)



# TODO (AV): move these functions to a more appropriate place
def fetch_channel_signing_data(signing_data_url, filename, etag=None, mod_stamp=None):
    if not context.ssl_verify:
        warnings.simplefilter('ignore', InsecureRequestWarning)

    session = CondaSession()

    headers = {}
    if etag:
        headers["If-None-Match"] = etag
    if mod_stamp:
        headers["If-Modified-Since"] = mod_stamp

    headers['Accept-Encoding'] = 'gzip, deflate, compress, identity'
    headers['Content-Type'] = 'application/json'

    try:
        timeout = context.remote_connect_timeout_secs, context.remote_read_timeout_secs
        file_url = join_url(signing_data_url, filename)

        # The `auth` arugment below looks a bit weird, but passing `None` seems
        # insufficient for suppressing modifying the URL to add an Anaconda
        # server token; for whatever reason, we must pass an actual callable in
        # order to suppress the HTTP auth behavior configured in the session.
        #
        # TODO (AV): Figure how to handle authn for obtaining trust metadata,
        # independently of the authn used to access package repositories.
        resp = session.get(file_url, headers=headers, proxies=session.proxies,
                           auth=lambda r: r, timeout=timeout)

        resp.raise_for_status()
    except:
        # TODO (AV): more sensible error handling
        raise

    # In certain cases (e.g., using `-c` access anaconda.org channels), the
    # `CondaSession.get()` retry logic combined with the remote server's
    # behavior can result in non-JSON content being returned.  Parse returned
    # content here (rather than directly in the return statement) so callers of
    # this function only have to worry about a ValueError being raised.
    try:
        str_data = json.loads(resp.content)
    except json.decoder.JSONDecodeError as err:  # noqa
        raise ValueError(f"Invalid JSON returned from {signing_data_url}/{filename}") from err

    # TODO (AV): additional loading and error handling improvements?

    return str_data


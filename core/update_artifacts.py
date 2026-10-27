"""Stage new immutable artifacts before maintenance; never switch a running node."""
import ast,hashlib,json
from pathlib import Path

def _prepare_artifacts(root,state=Path('/var/lib/filetrust-vaultkeeper')):
    root=Path(root);record=json.loads((root/'.filetrust-updates/prepared.json').read_text())
    payload=root/'.filetrust-updates/staging'/record['generation']/'code'
    data=(payload/'core/release.py').read_bytes()
    if hashlib.sha256(data).hexdigest()!=record['manifest']['files']['core/release.py']['sha256']:raise ValueError('Prepared release selector changed')
    tree=ast.parse(data);entries=[node for node in tree.body if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id=='ARTIFACT_TAG' for target in node.targets)]
    if len(entries)!=1:raise ValueError('Invalid artifact selector')
    tag=ast.literal_eval(entries[0].value)
    import re
    if not isinstance(tag,str) or not re.fullmatch(r'[A-Za-z0-9_.-]+',tag):raise ValueError('Invalid artifact tag')
    from node import prepare_release
    cfg=json.loads((state/'config.json').read_text())
    _verify_sources(payload,record)
    from go_build import build_runtime,using_build_spec
    with using_build_spec(payload/'core/go_build.py'):
        build_runtime(payload,output_root=root)
    manifest=prepare_release(state,cfg['download_profiles'],tag,allow_repair=False)
    from network import fetch,check_network
    from web3 import Web3
    check_network(Web3(Web3.HTTPProvider(cfg['rpc_url'],request_kwargs={'timeout':30})),cfg,manifest,fetch(cfg['network_config_url']))
    from ft_update_bootstrap import write_json
    write_json(root/'.filetrust-updates/artifacts-ready.json',{'generation':record['generation'],'package_sha256':record['package_sha256'],'tag':tag,'config_sha256':hashlib.sha256((state/'config.json').read_bytes()).hexdigest()})
    print('The required immutable runtime/profile bundles are staged; running files were not replaced.')

def prepare_artifacts(root,state=Path('/var/lib/filetrust-vaultkeeper')):
    from ft_update_install import update_lock
    with update_lock(Path(root)):
        return _prepare_artifacts(root,state)

def assert_prepared_artifacts(root,state=Path('/var/lib/filetrust-vaultkeeper')):
    root=Path(root);state=Path(state);control=root/'.filetrust-updates'
    record=json.loads((control/'prepared.json').read_text())
    try: ready=json.loads((control/'artifacts-ready.json').read_text())
    except (OSError,ValueError):raise ValueError('Artifact preparation is incomplete; run update prepare again') from None
    if (ready.get('generation')!=record['generation'] or ready.get('package_sha256')!=record['package_sha256']
        or ready.get('config_sha256')!=hashlib.sha256((state/'config.json').read_bytes()).hexdigest()):
        raise ValueError('Artifact preparation is incomplete or settings changed; prepare again')
    payload=control/'staging'/record['generation']/'code'
    _verify_sources(payload,record)
    from go_build import built_runtime,using_build_spec
    with using_build_spec(payload/'core/go_build.py'):
        built_runtime(payload,output_root=root)
    from node import release_manifest
    from artifact_store import installed,destination
    manifest=release_manifest(state,ready['tag'])
    cfg=json.loads((state/'config.json').read_text())
    selected={f'partition-{int(size)}' for size in cfg['download_profiles']}
    for bundle in manifest['bundles']:
        if bundle['id'] in selected and not installed(destination(state/'artifacts',bundle),bundle):
            raise ValueError('Prepared artifacts changed; repair before updating')


def _verify_sources(payload,record):
    from go_build import source_files
    for path in [*source_files(payload),payload/'core/go_build.py']:
        relative=str(path.relative_to(payload));expected=record['manifest']['files'].get(relative)
        if not expected or hashlib.sha256(path.read_bytes()).hexdigest()!=expected['sha256']:
            raise ValueError('Prepared Go source changed; prepare again')

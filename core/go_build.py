"""Verified Go toolchain and explicit local builds. Never invokes setup/generate.

The compiler pin is release-controlled. Private credentials and operator Go
settings are excluded from build subprocesses; module checksums remain enabled.
"""
from pathlib import Path
import ast,contextlib,hashlib,json,os,platform,re,shutil,subprocess,tarfile,tempfile,urllib.request
from vk_connect import urlopen

BUILD_FORMAT='CGO=0|runtime|trimpath|readonly|v1'
GO_VERSION='go1.26.10'
GO_ARCHIVE='go1.26.10.linux-amd64.tar.gz'
GO_SHA256='ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5'
GO_SIZE=66936659
WRAPPERS=('partition_prover_wrapper.sh','prover_wrapper.sh','prover_priority.sh')

def digest(path):
    result=hashlib.sha256()
    with Path(path).open('rb') as data:
        for chunk in iter(lambda:data.read(4*1024*1024),b''):result.update(chunk)
    return result.hexdigest()

def clean_environment():
    allowed={'PATH','HOME','TMPDIR','TMP','TEMP','LANG','LC_ALL','SSL_CERT_FILE','SSL_CERT_DIR'}
    return {key:value for key,value in os.environ.items() if key in allowed}


def version(path):
    try:
        result=subprocess.run([str(path),'version'],capture_output=True,text=True,check=True,env={**clean_environment(),'GOTOOLCHAIN':'local','GOENV':'off'},timeout=20)
        return result.stdout.split()[2]
    except (OSError,subprocess.SubprocessError,IndexError):return None

def extract_toolchain(archive,target,progress=print):
    with tarfile.open(archive,'r:gz') as package:
        members=package.getmembers()
        if len(members)>20000 or sum(member.size for member in members)>1024**3:raise ValueError('Go archive exceeds extraction limits')
        for member in members:
            path=Path(member.name)
            if not path.parts or path.parts[0]!='go' or path.is_absolute() or '..' in path.parts or not (member.isfile() or member.isdir()):raise ValueError('Unsafe Go archive member')
        last=-1
        for index,member in enumerate(members,1):
            # Explicit regular-file extraction also works on Python 3.10/3.11
            # without depending on backported tarfile extraction filters.
            output=Path(target)/member.name
            if member.isdir():output.mkdir(parents=True,exist_ok=True,mode=0o755)
            else:
                output.parent.mkdir(parents=True,exist_ok=True,mode=0o755)
                with package.extractfile(member) as source, output.open('xb') as destination:
                    shutil.copyfileobj(source,destination)
                output.chmod(0o755 if member.mode&0o111 else 0o644)
            percent=index*100//len(members)
            if percent//10!=last:progress('Go extraction: '+str(percent)+'%');last=percent//10

def ensure_go(cache,progress=print,allow_system=True):
    cache=Path(cache)
    if platform.system()!='Linux' or platform.machine()!='x86_64':raise ValueError('Local builds currently support Linux x86_64')
    system=shutil.which('go') if allow_system else None
    if system and version(system)==GO_VERSION:
        progress('Using installed '+GO_VERSION);return Path(system)
    tools=cache/'toolchains';tools.mkdir(parents=True,exist_ok=True)
    compiler=tools/GO_VERSION/'go/bin/go'
    if compiler.exists():
        if version(compiler)!=GO_VERSION:raise ValueError('Cached compiler changed; remove its toolchain cache before retrying')
        return compiler
    archive=tools/GO_ARCHIVE
    partial=archive.with_suffix('.part')
    if partial.exists() and partial.stat().st_size==GO_SIZE:
        if digest(partial)==GO_SHA256:os.replace(partial,archive)
        else:partial.unlink()
    if not archive.exists() or archive.stat().st_size!=GO_SIZE or digest(archive)!=GO_SHA256:
        partial=archive.with_suffix('.part');offset=partial.stat().st_size if partial.exists() else 0
        if offset>GO_SIZE:partial.unlink();offset=0
        progress('Installing verified '+GO_VERSION+' privately; system Go is unchanged')
        request=urllib.request.Request('https://go.dev/dl/'+GO_ARCHIVE,headers={'Range':f'bytes={offset}-','Accept-Encoding':'identity'})
        with urlopen(request,timeout=60) as response:
            if not response.url.startswith('https://'):raise ValueError('Insecure compiler redirect')
            if response.status==206:
                if response.headers.get('Content-Range')!=f'bytes {offset}-{GO_SIZE-1}/{GO_SIZE}':raise ValueError('Invalid compiler resume response')
            elif response.status==200:offset=0
            else:raise ValueError('Unexpected compiler download status')
            with partial.open('ab' if offset else 'wb') as output:
                last=-1
                while chunk:=response.read(1024*1024):
                    offset+=len(chunk)
                    if offset>GO_SIZE:raise ValueError('Compiler download exceeds pinned size')
                    output.write(chunk);percent=offset*100//GO_SIZE
                    if percent//5!=last:progress('Go download: '+str(percent)+'%');last=percent//5
        if offset!=GO_SIZE:raise ValueError('Compiler download interrupted; rerun to resume')
        if digest(partial)!=GO_SHA256:partial.unlink();raise ValueError('Compiler checksum mismatch')
        os.replace(partial,archive)
    with tempfile.TemporaryDirectory(prefix='.go-',dir=tools) as tmp:
        progress('Extracting checksum-verified '+GO_VERSION)
        extract_toolchain(archive,Path(tmp),progress=progress)
        if version(Path(tmp)/'go/bin/go')!=GO_VERSION:raise ValueError('Downloaded compiler version mismatch')
        os.replace(tmp,tools/GO_VERSION)
    return compiler

def source_files(root):
    root=Path(root)
    paths=[]
    for relative in ('runtime/code','runtime/prover'):
        directory=root/relative
        for path in sorted(directory.iterdir()):
            if path.name in ('go.mod','go.sum') or path.suffix=='.go':
                if path.is_symlink() or not path.is_file():raise ValueError('Source must be regular files')
                if path.name=='setup_factory.go' or path.name.endswith('_test.go'):raise ValueError('Factory/test source is not permitted in the public build')
                paths.append(path)
        if not (directory/'go.mod').is_file() or not (directory/'go.sum').is_file():raise ValueError('Missing pinned Go module files')
    for name in WRAPPERS:
        path=root/'runtime/wrappers'/name
        if path.is_symlink() or not path.is_file():raise ValueError('Wrapper source must be regular files')
        paths.append(path)
    return paths

def fingerprint(root):
    root=Path(root);h=hashlib.sha256(GO_VERSION.encode()+b'|'+BUILD_FORMAT.encode())
    for path in source_files(root):h.update(str(path.relative_to(root)).encode()+b'\0'+bytes.fromhex(digest(path)))
    return h.hexdigest()

def built_runtime(root,output_root=None):
    root=Path(root);output_root=Path(output_root or root);stamp=fingerprint(root);target=output_root/'bin'/stamp
    try:record=json.loads((target/'build.json').read_text())
    except (OSError,ValueError):raise ValueError('Local runtime is missing; rerun installation to compile it') from None
    if record.get('source_sha256')!=stamp or record.get('go_version')!=GO_VERSION or set(record.get('files',{}))!={'vaultmesh','storageproof-prover',*WRAPPERS}:raise ValueError('Invalid local build record')
    for name,expected in record['files'].items():
        path=target/name
        if path.is_symlink() or not path.is_file() or not os.access(path,os.X_OK) or digest(path)!=expected:raise ValueError('Local runtime changed; stop the node and rerun installation')
    return target

def build_environment(compiler,cache):
    compiler=Path(compiler);cache=Path(cache).resolve()
    return {**clean_environment(),'PATH':str(compiler.parent)+':/usr/bin:/bin','GOTOOLCHAIN':'local','GOENV':'off','GOWORK':'off','GOPROXY':'https://proxy.golang.org','GOSUMDB':'sum.golang.org','GONOSUMDB':'','GONOPROXY':'','GOPRIVATE':'','CGO_ENABLED':'0','GOCACHE':str(cache/'objects'),'GOMODCACHE':str(cache/'modules'),'GOFLAGS':'-mod=readonly','GOEXPERIMENT':''}

def build_runtime(root,output_root=None,progress=print,repair=False):
    root=Path(root).resolve();output_root=Path(output_root or root).resolve();stamp=fingerprint(root);target=output_root/'bin'/stamp
    if target.exists():
        try:
            result=built_runtime(root,output_root);progress("Local runtime already compiled; source/output checksums verified");return result
        except ValueError:
            if not repair:raise
            # Caller holds exclusive application/state locks while repairing.
            if target.is_symlink():raise ValueError('Cannot repair a symlink build path')
            shutil.rmtree(target)
    cache=output_root/'.build-cache';cache.mkdir(parents=True,exist_ok=True)
    if shutil.disk_usage(cache).free<3*1024**3:raise ValueError('Allow 3 GiB free for compiler, dependencies and build cache')
    compiler=ensure_go(cache,progress)
    environment=build_environment(compiler,cache)
    (output_root/'bin').mkdir(exist_ok=True)
    (output_root/'bin').chmod(0o755)
    with tempfile.TemporaryDirectory(prefix='.build-',dir=output_root/'bin') as temporary:
        staging=Path(temporary)
        snapshot=staging/'sources'
        for path in source_files(root):
            dest=snapshot/path.relative_to(root);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,dest)
        for index,(directory,name,tags) in enumerate([('code','vaultmesh',[]),('prover','storageproof-prover',['-tags=filetrust_runtime'])],1):
            progress(f'Build {index}/2: {name}; verify modules, then compile locally')
            cwd=snapshot/'runtime'/directory
            for label,command in [('Downloading pinned modules',[str(compiler),'mod','download']),('Verifying module checksums',[str(compiler),'mod','verify']),('Compiling '+name,[str(compiler),'build','-v','-mod=readonly','-trimpath','-buildvcs=false','-ldflags=-s -w',*tags,'-o',str(staging/name),'.'])]:
                progress(label)
                subprocess.run(command,cwd=cwd,env=environment,check=True)
        if fingerprint(snapshot)!=stamp:raise ValueError('Build changed pinned source/module checksums; refusing output')
        shutil.rmtree(snapshot)
        for name in WRAPPERS:shutil.copyfile(root/'runtime/wrappers'/name,staging/name)
        names=['vaultmesh','storageproof-prover',*WRAPPERS]
        for name in names:(staging/name).chmod(0o755)
        record={'schema':1,'source_sha256':stamp,'go_version':GO_VERSION,'files':{name:digest(staging/name) for name in names}}
        (staging/'build.json').write_text(json.dumps(record,sort_keys=True))
        (staging/'build.json').chmod(0o644)
        staging.chmod(0o755)
        os.replace(staging,target)
    progress('Local compilation complete; source and output checksums recorded')
    return target


@contextlib.contextmanager
def using_build_spec(path):
    """Read authenticated staged compiler data without executing staged code.

    Caller verifies this file against the prepared signed package first.
    Supported build algorithms stay fixed in the trusted current builder.
    """
    wanted={'GO_VERSION','GO_ARCHIVE','GO_SHA256','GO_SIZE','BUILD_FORMAT'};values={}
    for node in ast.parse(Path(path).read_bytes()).body:
        if isinstance(node,ast.Assign):
            for target in node.targets:
                if isinstance(target,ast.Name) and target.id in wanted:
                    if target.id in values:raise ValueError('Duplicate compiler specification')
                    values[target.id]=ast.literal_eval(node.value)
    if set(values)!=wanted or values['BUILD_FORMAT']!=BUILD_FORMAT:raise ValueError('Unsupported build format; use a reviewed full installer')
    if (not isinstance(values['GO_VERSION'],str) or not re.fullmatch(r'go[1-9]\d*\.\d+\.\d+',values['GO_VERSION'])
        or values['GO_ARCHIVE']!=values['GO_VERSION']+'.linux-amd64.tar.gz'
        or not isinstance(values['GO_SHA256'],str) or not re.fullmatch(r'[a-f0-9]{64}',values['GO_SHA256'])
        or type(values['GO_SIZE']) is not int or not 0<values['GO_SIZE']<256*1024**2):raise ValueError('Invalid compiler specification')
    previous={name:globals()[name] for name in wanted}
    try:
        globals().update(values)
        yield
    finally:globals().update(previous)


def compiled_with_current_go(binary,compiler,cache):
    result=subprocess.run([str(compiler),'version',str(binary)],capture_output=True,text=True,env=build_environment(compiler,cache))
    return result.returncode==0 and result.stdout.rstrip().endswith(': '+GO_VERSION)

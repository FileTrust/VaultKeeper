"""Warm the shared prover, start the server, then start its proof worker."""
from pathlib import Path
import re
import subprocess
import time
from console_progress import ConsoleProgress, READY, ADMISSION_OPEN, admission_event



class LogReader:
    def __init__(self,path):
        self.path=Path(path)
        self.offset=self.path.stat().st_size if self.path.exists() else 0
        self.partial=''

    def lines(self):
        if not self.path.exists():return []
        if self.path.stat().st_size<self.offset:self.offset=0;self.partial=''
        with self.path.open('r',errors='replace') as stream:
            stream.seek(self.offset);chunk=stream.read(65536);self.offset=stream.tell()
        rows=(self.partial+chunk).split('\n');self.partial=rows.pop()
        return rows


def run_workers(cfg,state,runtime,server,proof,environment,stop,lock_options,on_ready,log,on_started=None):
    """Use native admission readiness; process startup alone is not readiness."""
    state=Path(state);runtime=Path(runtime);processes=[];streams=[]
    logs=state/'logs';logs.mkdir(mode=0o700,parents=True,exist_ok=True)
    readers={name:LogReader(logs/(name+'.log')) for name in ('server','proof','prover')}
    console=ConsoleProgress(log)
    wrapper=str(runtime/'partition_prover_wrapper.sh')

    def start(name,command):
        stream=(logs/(name+'.log')).open('a');streams.append(stream)
        proc=subprocess.Popen(command,stdout=stream,stderr=subprocess.STDOUT,
                              env=environment,cwd=state,**lock_options)
        processes.append(proc)
        return proc

    def consume():
        lines=[]
        for name,reader in readers.items():
            for line in reader.lines():
                console.line(name,line)
                lines.append((name,line))
        return lines

    try:
        if cfg['storageproof_persistent_prover_enabled']:
            console.phase('Loading proof parameters into memory')
            warm=start('prover',[wrapper,'--start-service'])
            deadline=time.monotonic()+cfg['storageproof_persistent_prover_start_timeout_seconds']+30
            while warm.poll() is None:
                consume()
                console.tick()
                if stop.wait(.2):return
                if time.monotonic()>deadline:raise ValueError('Persistent prover startup timed out; see prover log')
            if warm.returncode!=0:raise ValueError('Persistent prover failed to start; see prover log')
            processes.remove(warm)
            console.phase('Proof parameters loaded; starting node')
        if stop.is_set():return
        worker=start('server',server)
        deadline=time.monotonic()+cfg['startup_timeout_sec'] if cfg['startup_timeout_sec'] else None
        server_started=False;admission_open=False;health_written=False
        while not stop.wait(.2):
            if any(proc.poll() is not None for proc in processes):
                raise ValueError('Node worker exited; see worker logs')
            for name,line in consume():
                if name=='server' and line.strip()=='FileTrust VK started':server_started=True
                if name in {'server','proof'}:
                    # Both workers compute and publish native admission. In a
                    # fresh node the proof worker commonly publishes the reopen.
                    event=admission_event(line)
                    if event is not None:
                        admission_open=event;console.admission(event)
                        if not event:health_written=False
            console.tick()
            if server_started and len(processes)==1:
                log('Server started; starting proof worker')
                start('proof',proof)
                if on_started is not None:on_started()
                console.phase('Preparing storage and initial proofs; uploads remain closed')
            if server_started and admission_open and not health_written:
                on_ready();health_written=True
                log('Vaultkeeper ready: admission open, accepting pieces')
                console.admission(True)
            if not server_started and deadline is not None and time.monotonic()>deadline:
                raise ValueError('Server did not start before startup_timeout_sec; see server log')
    finally:
        # Stop proof creation before the server; preserve RAM credentials until both exit.
        for proc in reversed(processes):
            if proc.poll() is None:proc.terminate()
        for proc in reversed(processes):proc.wait()
        subprocess.run([wrapper,'--stop-service'],env=environment,cwd=state,check=False)
        consume()
        for stream in streams:stream.close()

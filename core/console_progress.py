"""Calm operator output; original child output remains in the worker log files."""
import re
import time

ANSI=re.compile(r'\x1b\[[0-9;]*m')
READY=re.compile(r'(?:\[capacity-progress\]|(?:^|\s)capacity-progress)\s+READY(?: after [^\r\n]+)? -- admission open, accepting upload/download/delete$')
ADMISSION_OPEN=re.compile(r'(?:\[vk_adm\]|(?:^|\s)vk_adm)\s+ADMISSION (?:REOPENED|OPEN \(initial\))\s+safe=\d+\s*$')
ADMISSION_CLOSED=re.compile(r'(?:\[vk_adm\]|(?:^|\s)vk_adm)\s+ADMISSION CLOSED(?: \(initial\))?\s')


def admission_event(line):
    clean=ANSI.sub('',line)
    if READY.search(clean) or ADMISSION_OPEN.search(clean):return True
    if ADMISSION_CLOSED.search(clean):return False
    return None


class ConsoleProgress:
    def __init__(self,emit,clock=time.monotonic):
        self.emit=emit;self.clock=clock;self.seen={};self.last_activity=clock()
        self.stage='Starting node';self.started=clock()
        self.storage_percent=-5;self.storage_at=clock()
        self.ready=False;self.proofs=None;self.proof_changed_at=clock()

    def show(self,message):
        self.emit(message);self.last_activity=self.clock()

    def phase(self,message):
        if self.ready:return
        self.stage=message;self.started=self.clock();self.show(message)

    def admission(self,opened):
        if opened:
            self.ready=True;self.stage=None
        elif self.ready:
            self.ready=False
            self.phase('Uploads paused; waiting for native admission to reopen')

    def tick(self):
        if self.stage is not None and self.clock()-self.last_activity>=30:
            if self.proofs is not None:
                done,total=self.proofs;idle=int(self.clock()-self.proof_changed_at)
                warning='[WARN] ' if idle>=300 else ''
                if total>0 and done>=total:
                    self.show(f'{warning}All initial proofs confirmed; waiting for admission checks ({idle}s)')
                else:self.show(f'{warning}Waiting for next proof confirmation: {done} / {total} (no change for {idle}s)')
            else:self.show(f'{self.stage} — still working ({int(self.clock()-self.started)}s elapsed)')

    def line(self,name,raw):
        line=ANSI.sub('',raw)
        # Never suppress actual failures, even inside normally verbose subsystems.
        if re.search(r'\[FAIL\]|\b(panic|fatal|failed|error|corrupt|denied)\b',line,re.I):
            self.show(f'[{name}] {line}');return
        if re.search(r'\bfailures=[1-9]\d*',line) or ('proof-background' in line and 'warning' in line):
            self.show(f'[{name}] {line}');return
        if re.search(r'(?:\[capacity-urgency\]|(?:^|\s)capacity-urgency)\s+qualifiedLifecycleUrgency=false reason=no pending blocked demand\s*$',line):
            return  # Retained in the worker log; normal idle operation needs no console warning.
        wait=re.search(r'proof-background.*acquired .*wait=(\d+(?:\.\d+)?)(ms|s|m|h)',line)
        if wait and float(wait[1])*{'ms':.001,'s':1,'m':60,'h':3600}[wait[2]]>=30:
            self.show(f'Background proof work resumed after waiting {wait[1]}{wait[2]}');return
        prepared=re.search(r'(?:\[storage-preparation\]|(?:^|\s)storage-preparation)\s+completed_bytes=(\d+) total_bytes=(\d+)',line)
        if prepared:
            done,total=map(int,prepared.groups())
            percent=min(100,done*100//total) if total else 100
            text=f'Preparing storage: {done/1048576:.1f} / {total/1048576:.1f} MiB ({percent}%)'
            if self.seen.get('storage')!=text and (percent-self.storage_percent>=5 or
                    percent<self.storage_percent or percent==100 or self.clock()-self.storage_at>=30):
                self.storage_percent=percent;self.storage_at=self.clock()
                self.seen['storage']=text;self.phase(text)
            return
        if 'capacity-progress' in line:
            count=re.search(r'(\d+)/(\d+) partitions (\d+)% elapsed ([^ ]+)',line)
            if count:
                done,total,percent,elapsed=count.groups()
                observed=(int(done),int(total))
                if observed!=self.proofs:
                    self.proofs=observed;self.proof_changed_at=self.clock()
                    text=f'Initial proofs confirmed on-chain: {done} / {total} ({percent}%; elapsed {elapsed})'
                    if self.ready:self.show(text)
                    else:self.phase(text)
            elif 'building capacity baseline' in line:
                if self.seen.get('baseline') is None:
                    self.seen['baseline']=True;self.phase('Preparing initial proof schedule; uploads remain closed')
            # The supervisor consumes native readiness from either cooperating worker.
            return
        if re.search(r'proof-daemon\s+.*kind=capacity.*proving',line):
            self.phase('Generating an initial proof; waiting for calculation and chain confirmation');return
        if re.search(r'vk_reg\s+registered\s',line):
            self.show('Node registered on-chain');return
        if admission_event(line) is True:return
        if 'ADMISSION CLOSED' in line or 'admission status synced closed=true' in line:
            reason=re.search(r'reason=([^ ]+)',line)
            reason=reason.group(1) if reason else 'unknown'
            message=('Initializing proof service; uploads remain closed' if
                     reason=='proof_subsystem_unavailable' else f'Uploads paused: {reason}')
            key='admission:'+reason
            if self.clock()-self.seen.get(key,-1e12)>=60:
                self.seen[key]=self.clock();self.show(message)
            return
        if any(word in line for word in ('proof-background','chain-tx','partition-prover',
                                         'partition-service','zk_cache','background sector cache',
                                         'daily cleanup done','starting daily expired-sector',
                                         'continuous background reconcile','capacity-milestone')):
            return
        if re.search(r'\b(capacity|zk|proof-daemon|partition)\s',line) and '[WARN]' not in line:
            return
        # Preserve unrecognised messages and genuine warnings, but bound repeats.
        key=re.sub(r'\b\d{2}:\d{2}:\d{2}\b|\b(?:block|tx)=\S+','',line)
        key=name+':'+key
        if self.clock()-self.seen.get(key,-1e12)<60:return
        # Bound memory during a long-running service with many distinct events.
        if len(self.seen)>2048:self.seen={k:v for k,v in self.seen.items() if k=='storage' or k=='baseline' or isinstance(v,(int,float)) and self.clock()-v<60}
        self.seen[key]=self.clock();self.show(f'[{name}] {line}')

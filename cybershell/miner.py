from typing import List, Dict, Any
from pathlib import Path
import re, json
from dataclasses import dataclass
try:
    import yaml
except Exception:
    yaml = None
try:
    import PyPDF2
except Exception:
    PyPDF2 = None

@dataclass
class DocHit:
    title: str
    path: str
    summary: str
    score: float

class DocumentMiner:
    def __init__(self, root: str):
        self.root = Path(root)
        self.index: List[Dict[str, Any]] = []
        self.vocab: Dict[str, int] = {}

    def _textify(self, p: Path) -> str:
        t = p.suffix.lower()
        try:
            if t in {'.txt', '.md'}:
                return p.read_text(errors='ignore')
            if t == '.json':
                data = json.loads(p.read_text(errors='ignore') or '{}')
                return json.dumps(data, indent=2)
            if t in {'.yml', '.yaml'}:
                if yaml is None: return p.read_text(errors='ignore')
                data = yaml.safe_load(p.read_text(errors='ignore')) or {}
                return json.dumps(data, indent=2)
            if t in {'.html', '.htm'}:
                raw = p.read_text(errors='ignore')
                return re.sub('<[^>]+>', ' ', raw)
            if t == '.pdf' and PyPDF2 is not None:
                text = []
                with open(p, 'rb') as f:
                    reader = PyPDF2.PdfReader(f)
                    for pg in reader.pages:
                        text.append(pg.extract_text() or '')
                return '\n'.join(text)
            return p.read_text(errors='ignore')
        except Exception:
            return ''

    def _tokens(self, text: str):
        return re.findall(r'[a-z0-9_]{3,}', text.lower())

    def build(self):
        self.index.clear(); self.vocab.clear()
        docs = []
        for p in self.root.rglob('*'):
            if not p.is_file(): continue
            if p.suffix.lower() not in {'.txt','.md','.json','.yml','.yaml','.html','.htm','.pdf'}:
                continue
            text = self._textify(p)
            if not text.strip(): continue
            tokens = self._tokens(text)
            docs.append({'path': str(p), 'text': text, 'tokens': tokens})
        # df + tf-idf vecs
        from collections import Counter
        df = Counter()
        for d in docs:
            for t in set(d['tokens']):
                df[t]+=1
        self.vocab = {t:i for i,(t,_) in enumerate(df.most_common())}
        import math
        N = max(1, len(docs))
        for d in docs:
            tf = Counter(d['tokens'])
            vec = {}
            for t,c in tf.items():
                if t not in df: continue
                idf = math.log(1 + N/(1+df[t]))
                vec[self.vocab[t]] = (c/len(d['tokens'])) * idf
            d['vec'] = vec
            d['title'] = Path(d['path']).name
        self.index = docs

    def _vec_query(self, q: str):
        from collections import Counter
        tokens = self._tokens(q)
        tf = Counter(tokens)
        vec = {}
        for t,c in tf.items():
            if t not in self.vocab: continue
            vec[self.vocab[t]] = c/len(tokens)
        return vec

    @staticmethod
    def _cosine_sparse(a: Dict[int,float], b: Dict[int,float]) -> float:
        import math
        keys = set(a.keys()) & set(b.keys())
        dot = sum(a[k]*b[k] for k in keys)
        na = math.sqrt(sum(v*v for v in a.values())) or 1.0
        nb = math.sqrt(sum(v*v for v in b.values())) or 1.0
        return dot/(na*nb)

    def _summarize(self, text: str, query: str, max_sents: int = 5) -> str:
        sents = re.split(r'(?<=[.!?])\s+', text.strip())
        qtok = set(self._tokens(query))
        scored = []
        for s in sents:
            tok = set(self._tokens(s))
            if not tok: continue
            overlap = len(qtok & tok)/max(1,len(qtok))
            scored.append((overlap, s))
        scored.sort(reverse=True)
        return ' '.join(s for _,s in scored[:max_sents])

    def mine(self, query: str, top_k: int = 5) -> List[DocHit]:
        if not self.index: self.build()
        qv = self._vec_query(query)
        scored = []
        for d in self.index:
            sc = self._cosine_sparse(qv, d['vec'])
            if sc>0: scored.append((d, sc))
        scored.sort(key=lambda x: x[1], reverse=True)
        results = []
        for d,sc in scored[:top_k]:
            results.append(DocHit(
                title=d['title'],
                path=d['path'],
                summary=self._summarize(d['text'], query),
                score=float(sc)
            ))
        return results

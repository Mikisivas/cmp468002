"""LafiaAlert language engine.

* Multinomial Naive Bayes, written from scratch (no scikit-learn), with Laplace smoothing on
  word unigrams and bigrams. It classifies SMS reports written in English, Hausa or Nigerian
  Pidgin into incident types, plus a "noise" class for irrelevant or abusive texts.
* An urgency detector looks for words that mean "now", weapons or deaths in all three languages.
* A gazetteer matches town and village names to their LGA.

The training sentences are synthetic but use real Hausa and Pidgin phrasing; a real deployment
should retrain on labelled messages from the call centre.
"""
import json
import math
import os
import random
import re

import geo

URGENT = {"now", "yanzu", "currently", "happening", "gun", "guns", "bindiga", "bindigogi", "killed", "kill", "an kashe",
          "kashe", "dead", "burning", "kona", "help", "taimako", "attack", "hari", "matches", "machete", "adda"}

TEMPLATES = {
    "crop_destruction": [
        "cattle entered my {crop} farm at {place} and destroyed everything",
        "shanu sun shiga gonar {crop} a {place} sun lalata komai",
        "cow don chop all my {crop} for {place} farm",
        "herders grazed on our {crop} at {place} last night",
        "an lalata gonar {crop} a {place} da shanu",
        "dem push cow enter {crop} farm for {place} again",
        "our {crop} field near {place} was eaten by cattle",
    ],
    "cattle_rustling": [
        "thieves stole {n} cows from the herders camp at {place}",
        "barayi sun sace shanu {n} a {place}",
        "rustlers carry {n} cattle comot for {place} for night",
        "{n} cows were rustled near {place} this morning",
        "an sace shanu a ruga kusa da {place}",
    ],
    "armed_attack": [
        "gunmen attacked {place} now people are running",
        "an kai hari a {place} yanzu da bindigogi",
        "armed men don attack {place} dem dey shoot",
        "attack ongoing at {place} houses burning please help",
        "maharan sun kona gidaje a {place} an kashe mutane",
        "men with guns and machetes killed people in {place}",
    ],
    "threat": [
        "youths in {place} gave herders ultimatum to leave",
        "there is a threat that they will attack {place} on market day",
        "ana barazana cewa za a kai hari {place}",
        "people dey talk say dem go attack {place} soon",
        "hate messages circulating on whatsapp about {place}",
    ],
    "blocked_route": [
        "farmers blocked the cattle route near {place}",
        "an toshe hanyar shanu a {place}",
        "dem block the water point for {place} no cow fit drink",
        "the stream at {place} is fenced herders cannot pass",
    ],
    "noise": [
        "please send me recharge card",
        "good morning how is the family",
        "i want to buy fertilizer at {place} market",
        "sannu da aiki",
        "abeg wetin be the price of yam for {place}",
        "test test",
        "football match today at {place} stadium",
    ],
}
CROPS = ["yam", "maize", "rice", "cassava", "sorghum", "soybean", "dawa", "masara"]


def tokens(text):
    words = re.findall(r"[a-z']+", text.lower())
    return words + [f"{a}_{b}" for a, b in zip(words, words[1:])]


def corpus(n_per_class=120, seed=7):
    rnd = random.Random(seed)
    places = [p for names in geo.cfg()["gazetteer"].values() for p in names]
    out = []
    for label, temps in TEMPLATES.items():
        for _ in range(n_per_class):
            t = rnd.choice(temps).format(place=rnd.choice(places), crop=rnd.choice(CROPS), n=rnd.randint(3, 60))
            words = t.split()
            if rnd.random() < 0.3:  # typing noise: drop a word
                words.pop(rnd.randrange(len(words)))
            out.append((" ".join(words), label))
    rnd.shuffle(out)
    return out


class NaiveBayes:
    def fit(self, data, alpha=1.0):
        self.alpha = alpha
        self.classes = sorted({y for _, y in data})
        self.prior = {c: math.log(sum(1 for _, y in data if y == c) / len(data)) for c in self.classes}
        self.counts = {c: {} for c in self.classes}
        self.totals = {c: 0 for c in self.classes}
        vocab = set()
        for x, y in data:
            for t in tokens(x):
                self.counts[y][t] = self.counts[y].get(t, 0) + 1
                self.totals[y] += 1
                vocab.add(t)
        self.V = len(vocab)
        return self

    def proba(self, text):
        toks = tokens(text)
        logp = {}
        for c in self.classes:
            denom = self.totals[c] + self.alpha * self.V
            logp[c] = self.prior[c] + sum(math.log((self.counts[c].get(t, 0) + self.alpha) / denom) for t in toks)
        m = max(logp.values())
        ex = {c: math.exp(v - m) for c, v in logp.items()}
        s = sum(ex.values())
        return {c: v / s for c, v in ex.items()}

    def predict(self, text):
        p = self.proba(text)
        best = max(p, key=p.get)
        return best, p[best]

    def save(self, path):
        json.dump({"alpha": self.alpha, "classes": self.classes, "prior": self.prior, "counts": self.counts,
                   "totals": self.totals, "V": self.V}, open(path, "w"))

    @classmethod
    def load(cls, path):
        m = cls()
        m.__dict__.update(json.load(open(path)))
        return m


def evaluate(model, test):
    labels = model.classes
    cm = {a: {b: 0 for b in labels} for a in labels}
    for x, y in test:
        cm[y][model.predict(x)[0]] += 1
    per = {}
    for c in labels:
        tp = cm[c][c]
        fp = sum(cm[o][c] for o in labels if o != c)
        fn = sum(cm[c][o] for o in labels if o != c)
        p = tp / (tp + fp) if tp + fp else 0
        r = tp / (tp + fn) if tp + fn else 0
        per[c] = {"precision": round(p, 3), "recall": round(r, 3), "f1": round(2 * p * r / (p + r), 3) if p + r else 0}
    acc = sum(cm[c][c] for c in labels) / len(test)
    return {"accuracy": round(acc, 3), "per_class": per, "confusion": cm, "test_size": len(test)}


def train(path):
    data = corpus()
    cut = int(len(data) * 0.75)
    m = NaiveBayes().fit(data[:cut])
    ev = evaluate(m, data[cut:])
    m.save(path)
    return ev


def urgent(text):
    low = text.lower()
    return any(re.search(rf"\b{re.escape(w)}\b", low) for w in URGENT)


def geocode(text):
    low = text.lower()
    for lga_name, places in geo.cfg()["gazetteer"].items():
        for p in sorted(places, key=len, reverse=True):
            if re.search(rf"\b{re.escape(p)}\b", low):
                return lga_name, p
    return None, None

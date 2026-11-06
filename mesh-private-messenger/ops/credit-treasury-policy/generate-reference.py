#!/usr/bin/env python3
"""Independent Python integer model for the exact supplied revenue policy."""
import hashlib
import json
from pathlib import Path
POLICIES = {
  1: 'morse-credit-revenue-split-v1:witness=floor((gross+carry)/5);operations=remainder;carry=mod5',
  2: 'morse-credit-revenue-split-v2:gross=2/10,3/10,5/10;carry=per-share-numerator;reserve=sum-carry/10',
}
def model(version,amount,carries):
  if version == 1:
    assert 0 <= carries[0] < 5 and carries[1:] == [0,0]
    witness,remainder = divmod(amount+carries[0],5)
    shares=[witness,0,amount-witness]
    following=[remainder,0,0]
    reserve_before=reserve_after=0
  else:
    assert all(0 <= c < 10 for c in carries) and sum(carries)%10 == 0
    shares,following = [],[]
    for numerator,carry in zip([2,3,5],carries):
      quotient,remainder=divmod(amount*numerator+carry,10)
      shares.append(quotient);following.append(remainder)
    reserve_before=sum(carries)//10;reserve_after=sum(following)//10
    assert sum(shares)+reserve_after == amount+reserve_before
  assert all(q>=0 for q in shares)
  return {'version':version,'amount':str(amount),'carries':carries,'shares':[str(q) for q in shares],
          'next_carries':following,'reserve_before':reserve_before,'reserve_after':reserve_after,
          'policy_hash':hashlib.sha256(POLICIES[version].encode()).hexdigest()}
cases=[]
for version in [1,2]:
  for amount in list(range(21))+[1_000_001,2**53+1,2**64-1]:
    cases.append(model(version,amount,[0,0,0]))
for carries in [[0,5,5],[2,3,5],[4,6,0],[6,9,5],[8,2,0],[9,9,2],[1,0,9],[9,1,0]]:
  for amount in [0,1,3,9,20,2**64-1]:cases.append(model(2,amount,carries))
for c in range(5):
  for amount in [0,1,4,5,2**64-1]:cases.append(model(1,amount,[c,0,0]))
Path(__file__).with_name('fixtures').joinpath('model.json').write_text(json.dumps({'schema_version':1,'cases':cases},indent=2)+'\n')

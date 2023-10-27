# Implementation of Mutual Restraining E-voting system

## Description
This is a python implementation of mutual restraining evoting system, as proposed by Dr. Xukai Zou.

## Requirements
Tested and executed in Python 3.11.1\
Requires a paillier cryptosystem library which can be installed using `pip install phe`

## How to run
1. Run `server.py` with the desired number of candidates and voters for class initialization `Election(candidates, voters)`
2. Open two terminal windows for each collector and run `collector.py`
3. Open a terminal window for each voter and run `voter.py`
4. After collectors have started server, press Enter on each voter's terminal window to have them connect to collectors and cast vote.
5. Both collectors will tally votes, display ballots, and validate ballots, and election will be complete.
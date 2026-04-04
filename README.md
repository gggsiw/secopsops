# SecOpsOps OpenEnv

Security Operations Center simulation environment for AI agents.

## Tasks
- Easy: Malicious IP detection
- Medium: Brute-force login detection
- Hard: Multi-step attack chain

## Run

docker build -t secopsops .


docker run -e HF_TOKEN=your_key secopsops


## TO RUN inference.py FILE 

export  HF_TOKEN=your_key


python inference.py

# EDNS Client Subnet Measurement
## About the project
This repository contains all the scripts we used to conduct an EDNS measurement as part of a university project.

We are measuring support for and implementation of the EDNS Client Subnet extension.
We want to analyze how widely this DNS extension is deployed and how different DNS Resolvers are making use of it.

In our Approach, we will query authoritative nameservers for A records with different EDNS Client Subnets.

## Repo Structure
`/analysis`:
 - python & jupyter notebook scripts to generate plots based on the measurement data we acquired
 - the data is analyzed with [pandas](https://pandas.pydata.org/) and the plots are generated with [matplotlib](https://matplotlib.org/)

`/scan`: 
- this contains the main scanner implemented in go
- the scanner operates in **two** phases
- **first** phase: recursive resolving of the authoritative nameservers for the provided list of domains
- **second** phase: querying the authoritative nameservers with multiple manually pre-selected subnets

## How to run?
0. clone this repo `git clone https://github.com/f10d0/edns_subnet_measurement && cd edns_subnet_measurement`

1. to run the **scanner** you need a few things:
  
- you need to have [go](https://go.dev/doc/install) installed
- a **list of domains** you want to scan, e.g. the [tranco](https://tranco-list.eu/) toplist
- a **list of subnets** in CIDR notation to scan against in the second phase (we will not provide this)

2. copy the template config `cp scan/config.yml.template scan/config.yml` and adjust the locations to the lists & and other configurations parameters (like verbosity and the number of go routines during scan) as needed

3. run the scan `cd scan && go run ecs_scan.go` -> this will write all the important results to a file called `scan.csv.gz`

4. for the **analysis** part you need a geolocation database (containing country & ASN information)
- this was done with the free version of the [ipinfo.io](https://ipinfo.io/) database which can be downloaded after sign-up on their website (in `.mmdb` MaxMind database format)
- be aware that using any other database will probably need code adjustments as the formats might differ

5. create a python venv in the root of this project & and install the python requirements

   `python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`

6. open the jupyter notebook `analysis/graphs.ipynb` & set the paths to the database, scan files & plots how you like

7. run the cells you want to generate the plots (first two cells are mandatory)

**Keep in mind that this will generate a lot of DNS-Requests with high packet rate and should probably not be run from a network that was not made for this kind of scan**
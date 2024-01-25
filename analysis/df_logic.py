import numpy as np
import pandas as pd
import os
import geoip2.database
import geoip2.errors
import geopy
from typing import Tuple

# INITS
database_cache = {}
distance_cache = {}

def init_geo(geoip_db_path: str):
    global geo_reader
    geo_reader = geoip2.database.Reader(geoip_db_path)

# function to load scan an "unenriched" csv
def load_csv(csv_path, usecols=None) -> pd.DataFrame:

    df = pd.read_csv(csv_path,
                     header=None,
                     sep=";",
                     names=["timestamp", "domain", "ns-ip", "subnet", "returned-subnet", "scope", "returned-ips"],
                     usecols=usecols,
                     dtype={"timestamp": str,
                            "domain": str,
                            "ns-ip": str,
                            "subnet": str,
                            "returned-subnet": str,
                            "scope": float,
                            "returned-ips": str})
    return df

# function to load a scan csv enriched with geolocation data
def load_enriched_csv(csv_path, usecols=None) -> pd.DataFrame:

    df = pd.read_csv(csv_path,
                     header=None,
                     sep=";",
                     names=["timestamp", "domain", "ns-ip",
                            "subnet", "subnet-scope", "subnet-location",
                            "returned-subnet", "scope", "returned-ips",
                            "ip-locations", "average-distance"],
                     usecols=usecols,
                     dtype={"timestamp": str,
                            "domain": str,
                            "ns-ip": str,
                            "subnet": str,
                            "subnet-scope": float,
                            "returned-subnet": str,
                            "scope": float,
                            "returned-ips": str,
                            "average-distance": float})
    return df

# format is still cursed but here we go
# lat, long, country_iso_code, accuracy_radius, continent_code
def ip_to_location(ip: str) -> Tuple[str, str, int]:

    if ip in database_cache:
        return database_cache[ip]

    try:
        city_resp = geo_reader.city(ip)
    except geoip2.errors.AddressNotFoundError:
        return None, None, None, None, None

    # TODO i feel like this database_cache is probably not needed
    # or is it?
    database_cache[ip] = city_resp.location.latitude, city_resp.location.longitude, city_resp.country.iso_code, city_resp.location.accuracy_radius, city_resp.continent.code
    return database_cache[ip]

def ips_to_location(ips):
    if type(ips) is float:
        return np.nan
    iplist = str.split(ips, ",")
    locations = []
    for ip in iplist:
        locations.append(ip_to_location(ip))
    return locations

# function to calculate the average distance from an ip to other ips
def average_distance(subnet_location, ip_locations):
    if type(subnet_location) is float or type(ip_locations) is float:
        return np.nan
    if subnet_location[1] is None:
        return np.nan
    distances = []
    for ip_location in ip_locations:
        if ip_location[1] is None:
            continue
        if (subnet_location[0], ip_location[0]) in distance_cache:
            distances.append(distance_cache[subnet_location[0], ip_location[0]])
            continue
        distance = geopy.distance.geodesic(subnet_location[0], ip_location[0]).km
        distance_cache[subnet_location[0], ip_location[0]] = distance
        distances.append(distance)
    if not distances:
        return np.nan
    average_dist = sum(distances) / len(distances)
    return average_dist

# enriches csv with geolocation data. Process takes times mainly because calculating distance is slow
def create_enriched_data(csv_path: str, enr_path: str, truncate=False):
    if os.path.exists(enr_path):
        if truncate:
            print("truncating enriched CSV file")
            os.unlink(enr_path)
        else:
            print("enriched CSV file already exists")
            return
    chunk_size = 10 ** 6 * 5

    print("now creating enriched CSV file in chunks")

    with pd.read_csv(csv_path,
                     chunksize=chunk_size,
                     header=None,
                     sep=";",
                     names=["timestamp", "domain", "ns-ip", "subnet", "returned-subnet", "scope", "returned-ips"],
                     usecols=["timestamp", "domain", "ns-ip", "subnet", "returned-subnet", "scope", "returned-ips"],
                     dtype={"timestamp": str,
                            "domain": str,
                            "ns-ip": str,
                            "subnet": str,
                            "returned-subnet": str,
                            "scope": float,
                            "returned-ips": str}) as csvreader:

        for index, chunk in enumerate(csvreader):

            chunk[["subnet", "subnet-scope"]] = chunk["subnet"].str.split("/", expand=True)

            chunk["subnet-location"] = chunk["subnet"].apply(ip_to_location)
            chunk["ip-locations"] = chunk["returned-ips"].apply(ips_to_location)
            # chunk["average-distance"] = chunk.apply(
            #     lambda row: average_distance(row["subnet-location"], row["ip-locations"]), axis=1)
            chunk["average-distance"] = np.nan

            # rearrange the columns a bit
            chunk = chunk[["timestamp", "domain", "ns-ip",
                           "subnet", "subnet-scope", "subnet-location",
                           "returned-subnet", "scope", "returned-ips",
                           "ip-locations", "average-distance"]]

            chunk.to_csv(enr_path, compression="gzip", index=False, mode="a", header=False, sep=";")
            print(f"chunk {index} completed")
    print("done creating enriched CSV file")
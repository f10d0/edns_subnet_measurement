import numpy as np
import pandas as pd
import os
import geoip2.database
import geoip2.errors
import geopy.distance

# Dicts for simple caching
database_cache = {}
distance_cache = {}

reader = geoip2.database.Reader('GeoLite2-City_20240109/GeoLite2-City.mmdb')
relative_file_path = "csvs/scan.csv.gz"
data_path = os.path.join(os.getcwd(), relative_file_path)
plot_path = os.path.join(os.getcwd(), "plots")
# Directory for the plots
if not os.path.exists(plot_path):
    os.mkdir(plot_path)


# Plot for the Percentage of Responses that contain an ECS Field
# requires "returned-subnet" columns
def plot_ecs_support_percentage(df):

    if "returned-subnet" not in df.columns:
        print("Missing 'returned-subnet' column")
        return
    no_returned_ecs = df["returned-subnet"].isna().sum()
    returned_ecs = df["returned-subnet"].dropna().count()
    ecs_fields = pd.DataFrame({"ECS field in response": [returned_ecs, no_returned_ecs]}, index=["yes", "no"])
    plot = ecs_fields.plot.pie(y=0, legend=False, autopct='%1.1f%%')
    plot.get_figure().savefig(os.path.join(plot_path, "ECS_field_in_response.png"))


# Plot for the Distribution of Prefix lengths
# requires "scope" column and "timestamp" column for counting <- change this
def plot_returned_scopes(df):

    if "scope" and "timestamp" not in df.columns:
        print("Missing 'timestamp' or 'scope' column")
        return
    return_scopes = df.groupby("scope").count()
    return_scopes = return_scopes[["timestamp"]]
    return_scopes = return_scopes.rename(columns={"timestamp": "count"})
    plot = return_scopes.plot.bar(y='count', legend=False)
    plot.set_ylabel("number of responses")
    plot.get_figure().savefig(os.path.join(plot_path, "return_scopes.png"))


# Plot for Prefix lengths in comparison to the input length
# requires "subnet", "scope"
# also works if "subnet" already has been split in "subnet" and "subnet-scope"
def plot_returned_scope_comparison(df):

    if "scope" and "subnet" not in df.columns:
        print("Missing 'scope' or 'subnet' column")
        return
    if "subnet-scope" not in df.columns:
        df[["subnet", "subnet-scope"]] = df["subnet"].str.split("/", expand=True)
    scopes = df[["subnet-scope", "scope"]].dropna()
    scopes["subnet-scope"] = scopes["subnet-scope"].astype(int)
    scopes["scope"] = scopes["scope"].astype(int)
    # There must be a better way to calculate this, but this works for now
    same = len(scopes[scopes["scope"] == scopes["subnet-scope"]])
    less_specific = len(scopes[(scopes["scope"] < scopes["subnet-scope"]) & (scopes["scope"] != 0)])
    more_specific = len(scopes[scopes["scope"] > scopes["subnet-scope"]])
    zero_specific = len(scopes[scopes["scope"] == 0])
    compare_scopes = pd.DataFrame(data={"edns response scope": [same, zero_specific, less_specific, more_specific]},
                                  index=["same prefix length", "no prefix", "less specific prefix (none 0)", "more specific prefix"])
    plot = compare_scopes.plot.pie(y=0, legend=False, autopct='%1.1f%%')
    plot.get_figure().savefig(os.path.join(plot_path, "compare_scopes.png"))


# plots CDF for average-distances
# requires "average-distance" column
def plot_distance_cdf(df):

    if "average-distance" not in df.columns:
        print("Missing 'average-distance' column")
        return
    cdf = pd.DataFrame(df["average-distance"])
    cdf["cdf"] = cdf.rank(method="average", pct=True)
    ax = cdf.sort_values("average-distance").plot(x="average-distance", y="cdf", grid=True)
    ax.get_figure().savefig(os.path.join(plot_path, "distance_cdf.png"))


# The way the data is saved is pretty cursed ngl, but it works I guess... for now
# get the location data ((longitude, latitude), country_code, accuracy)
def ip_to_location(ip):

    if ip in database_cache:
        return database_cache[ip]

    try:
        response = reader.city(ip)
    except geoip2.errors.AddressNotFoundError:
        return (None, None), None, None

    database_cache[ip] = (response.location.latitude,
                          response.location.longitude), response.country.iso_code, response.location.accuracy_radius
    return (response.location.latitude,
            response.location.longitude), response.country.iso_code, response.location.accuracy_radius


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
def create_enriched_data(csv):

    chunk_size = 10 ** 6 * 5
    with pd.read_csv(csv,
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

        for chunk in csvreader:

            chunk[["subnet", "subnet-scope"]] = chunk["subnet"].str.split("/", expand=True)

            chunk["subnet-location"] = chunk["subnet"].apply(ip_to_location)
            chunk["ip-locations"] = chunk["returned-ips"].apply(ips_to_location)

            chunk["average-distance"] = chunk.apply(
                lambda row: average_distance(row["subnet-location"], row["ip-locations"]), axis=1)

            # rearrange the columns a bit
            chunk = chunk[["timestamp", "domain", "ns-ip",
                           "subnet", "subnet-scope", "subnet-location",
                           "returned-subnet", "scope", "returned-ips",
                           "ip-locations", "average-distance"]]

            chunk.to_csv("csvs/enriched_scan.csv.gz", compression="gzip", index=False, mode="a", header=False, sep=";")
            print("chunk completed")


# function to load a scan csv enriched with geolocation data
def load_enriched_csv(csv_path, usecols):

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


def main():

    df = pd.read_csv("csvs/scan.csv.gz",
                     header=None,
                     sep=";",
                     names=["timestamp", "domain", "ns-ip", "subnet", "returned-subnet", "scope", "returned-ips"],
                     usecols=["timestamp", "scope"],
                     dtype={"timestamp": str,
                            "domain": str,
                            "ns-ip": str,
                            "subnet": str,
                            "returned-subnet": str,
                            "scope": float,
                            "returned-ips": str})

    plot_returned_scopes(df)

    # plot_ecs_support_percentage(df)
    # plot_returned_scope_comparison(df)

    # create_enriched_data("csvs/scan_2024-01-20_01-00_UTC_fixed.csv.gz")

    # df = load_enriched_csv("csvs/enriched_scan.csv.gz", usecols=["domain", "average-distance"])
    # df = df.groupby(by=["domain"]).mean().sort_values(by="average-distance", ascending=True)
    # ax = df.plot()
    # ax.get_figure().savefig(os.path.join(plot_path, "distances.png"))

    # plot_distance_cdf(df)



if __name__ == "__main__":
    main()
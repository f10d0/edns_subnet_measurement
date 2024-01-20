import numpy as np
import pandas as pd
import os
import geoip2.database
import geoip2.errors
import geopy.distance


def average_distance(ns_location, ip_locations):
    if type(ns_location) is float or type(ip_locations) is float:
        return np.nan
    if ns_location[1] is None:
        return np.nan
    distances = []
    for ip_location in ip_locations:
        if ip_location[1] is None:
            continue
        distances.append(geopy.distance.geodesic(ns_location[0], ip_location[0]).km)
    if not distances:
        return np.nan
    average_dist = sum(distances) / len(distances)
    return average_dist

# TODO Make functions out of this mess to make it at lot more readable
# Create Directory for the plots
plot_path = os.path.join(os.getcwd(), "plots")
if not os.path.exists(plot_path):
    os.mkdir(plot_path)

relative_file_path = "scan_2024-01-20_01-00_UTC_fixed.csv.gz"
data_path = os.path.join(os.getcwd(), relative_file_path)

# Read the data
df = pd.read_csv(data_path, header=None, sep=";", names=["timestamp", "domain", "ns-ip", "subnet", "returned-subnet", "scope", "returned-ips"])

# Plot for the Percentage of Responses that contain an ECS Field
no_returned_ECS = df["returned-subnet"].isna().sum()
returned_ECS = df["returned-subnet"].dropna().count()
ECS_fields = pd.DataFrame({"ECS field in response": [returned_ECS, no_returned_ECS]}, index=["yes", "no"])
plot = ECS_fields.plot.pie(y=0, legend=False, autopct='%1.1f%%')
plot.get_figure().savefig(os.path.join(plot_path, "ECS_field_in_response.png"))


df[["subnet", "subnet-scope"]] = df["subnet"].str.split("/", expand=True)

# Plot for the Distribution of Prefix lengths
return_scopes = df.groupby("scope").count()
return_scopes = return_scopes[["timestamp"]]
return_scopes = return_scopes.rename(columns={"timestamp": "count"})
plot = return_scopes.plot.bar(y='count', legend=False)
plot.set_ylabel("number of responses")
plot.get_figure().savefig(os.path.join(plot_path, "return_scopes.png"))

# Plot for Prefix lengths in comparison to the input length
scopes = df[["subnet-scope","scope"]].dropna()
scopes["subnet-scope"] = scopes["subnet-scope"].astype(int)
scopes["scope"] = scopes["scope"].astype(int)
# There must be a better way to calculate this, but this works for now
same = len(scopes[scopes["scope"] == scopes["subnet-scope"]])
less_specific = len(scopes[(scopes["scope"] < scopes["subnet-scope"]) & (scopes["scope"] != 0)])
more_specific = len(scopes[scopes["scope"] > scopes["subnet-scope"]])
zero_specific = len(scopes[scopes["scope"] == 0])
compare_scopes = pd.DataFrame({"edns response scope": [same, zero_specific, less_specific, more_specific]}, index=["same prefix length", "no prefix", "less specific prefix (none 0)", "more specific prefix"])
plot = compare_scopes.plot.pie(y=0, legend=False, autopct='%1.1f%%')
plot.get_figure().savefig(os.path.join(plot_path, "compare_scopes.png"))

# enriching the data with information form GeoLite2 Database
# TODO pull out the functions from here, it's pretty cursed at the moment
# TODO the way the data is saved is also pretty cursed ngl but it works i guess... for now
with geoip2.database.Reader('GeoLite2-City_20240109/GeoLite2-City.mmdb') as reader:
    cache = {}

    def ip_to_location(ip):

        if ip in cache:
            return cache[ip]

        try:
            response = reader.city(ip)
        except geoip2.errors.AddressNotFoundError:
            return (None, None), None, None

        cache[ip] = (response.location.latitude,
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

    df["ns-location"] = df["ns-ip"].apply(ip_to_location)
    df["ip-locations"] = df["returned-ips"].apply(ips_to_location)

df["average-distance"] = df.apply(lambda row: average_distance(row["ns-location"], row["ip-locations"]), axis=1)
df_average = df[df["average-distance"].notna()]
df_average["average-distance"] = df_average["average-distance"].astype(float)
print(df_average[["domain", "average-distance"]].groupby("domain").mean().sort_values(by="average-distance", ascending=False).head())

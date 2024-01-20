import pandas as pd
import os

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
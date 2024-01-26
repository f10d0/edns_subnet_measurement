import pandas as pd
import os
import matplotlib.pyplot as plt
from ast import literal_eval

def plot_ecs_support_percentage(df, plot_path):
    """
    Plot for the Percentage of Responses that contain an ECS Field
    requires "returned-subnet" columns
    """

    if "returned-subnet" not in df.columns:
        print("Missing 'returned-subnet' column")
        return
    no_returned_ecs = df["returned-subnet"].isna().sum()
    returned_ecs = df["returned-subnet"].dropna().count()
    ecs_fields = pd.DataFrame({"ECS field in response": [returned_ecs, no_returned_ecs]}, index=["yes", "no"])
    plot = ecs_fields.plot.pie(y=0, legend=False, autopct='%1.1f%%')
    plot.get_figure().savefig(os.path.join(plot_path, "ECS_field_in_response.png"))


def plot_returned_scopes(df, plot_path):
    """
    Plot for the Distribution of Prefix lengths
    requires "scope" column and "timestamp" column for counting <- change this
    """

    if "scope" and "timestamp" not in df.columns: # FIXME i dont think this does what it should -> if "scope" is always true
        print("Missing 'timestamp' or 'scope' column")
        return
    return_scopes = df.groupby("scope").count()
    return_scopes = return_scopes[["timestamp"]]
    return_scopes = return_scopes.rename(columns={"timestamp": "count"})
    plot = return_scopes.plot.bar(y='count', legend=False)
    plot.set_ylabel("number of responses")
    plot.get_figure().savefig(os.path.join(plot_path, "return_scopes.png"))


def plot_returned_scope_comparison(df, plot_path):
    """
    Plot for Prefix lengths in comparison to the input length
    requires "subnet", "scope"
    also works if "subnet" already has been split in "subnet" and "subnet-scope"
    """

    if "scope" and "subnet" not in df.columns: # FIXME i dont think this does what it should
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

# FIXME this is not the plot we originally wanted though i think, we need to average the averages
def plot_distance_cdf(df, plot_path):
    """
    plots CDF for average-distances for domains
    only takes domains, which got distances for at least 10 different subnets in order to filter out some outliers
    requires "average-distance" and "scope" column
    """

    if "average-distance" and "scope" not in df.columns: # FIXME i dont think this does what it should
        print("Missing 'average-distance' or 'scope' column")
        return

    ecs_df = df[df["scope"].notna()]
    non_ecs_df = df[df["scope"].isna()]
    ax = None

    for sub_df in [ecs_df, non_ecs_df]:
        cdf = pd.DataFrame(sub_df["average-distance"])
        cdf["cdf"] = cdf.rank(method="average", pct=True)
        if not ax:
            ax = cdf.sort_values("average-distance").plot(x="average-distance", y="cdf", grid=True, kind="line")
        elif ax:
            ax = cdf.sort_values("average-distance").plot(x="average-distance", y="cdf", grid=True, kind="line", ax=ax)

    ax.get_figure().savefig(os.path.join(plot_path, "distance_cdf.png"))

def plot_continent_distribution(df, plot_path, ecs=True):
    """
    in theory this plots the frequency of how often the subnet used for a request matches its answer over all the domains
    takes dataframe with domain, scope, subnet-location, ip-locations
    """

    if any(column not in df.columns for column in ["domain", "scope", "subnet-location", "ip-locations"]):
        print("Missing columns")
        return

    def process_group(group):
            match_count = 0
            for _, row in group.iterrows():
                subnet_continent = row['subnet-location']  # Extracting the continent code of subnet-location
                subnet_continent = literal_eval(subnet_continent)[4]
                ip_locations = row['ip-locations']
                if pd.isna(ip_locations):
                    break
                ip_locations = literal_eval(ip_locations)
                for valid_ip_loc in ip_locations:
                    ip_loc_continent = valid_ip_loc[4]  # Extracting the continent code of the first valid ip-location
                    if ip_loc_continent:
                        if subnet_continent == ip_loc_continent:
                            match_count += 1
                            break
            return match_count
    
    if ecs:
        df = df[df["scope"].notna()]
    else:
        df = df[df["scope"].isna()]
    grouped = df.groupby('domain')
    match_counts = grouped.apply(process_group)

    aggregated_counts = match_counts.value_counts().sort_index()

    # Plotting
    aggregated_counts.plot(kind='bar')
    plt.xlabel('Number of Matching Continent Codes')
    plt.ylabel('Number of Domains')
    if ecs:
        plt.title('Distribution of Matching Continent Codes per Domain (ECS present)')
        plt.savefig(os.path.join(plot_path,"continent_distribution_ecs.png"))
    else:
        plt.savefig(os.path.join(plot_path,"continent_distribution_noecs.png"))

def plot_country_responses(df, plot_path, ecs=True):
    """
    this theoretically creates a graph of how many responses we get in total (excluding non ecs) per country
    takes dataframe with domain, scope, subnet-location, ip-locations
    """

    if any(column not in df.columns for column in ["domain", "scope", "subnet-location", "ip-locations"]):
        print("Missing columns")
        return

    if ecs:
        df = df.dropna(subset=["scope","ip-locations"])
    else:
        df = df.dropna(subset=["scope"], how='any')
        df = df.dropna(subset=["ip-locations"])
    country_amount = {}
    for _, group in df.groupby('domain'):
        for _, row in group.iterrows():
            ip_locations = row["ip-locations"]
            ip_locations = literal_eval(ip_locations)
            for valid_ip_loc in ip_locations:
                country_code = valid_ip_loc[2] #country code
                if country_code:
                    if country_code in country_amount:
                        country_amount[country_code] += 1
                    else:
                        country_amount[country_code] = 0

    df = pd.DataFrame(list(country_amount.items()), columns=['CountryCode', 'Amount'])

    # Sort the DataFrame by the 'Amount' column in ascending order
    df = df.sort_values(by='Amount')
    df = df[df['Amount'] >= 10000]

    # Create the bar plot
    plt.figure(figsize=(10, 6))  # Adjust the figure size as needed
    plt.bar(df['CountryCode'], df['Amount'], color='skyblue')
    plt.xlabel('Country Code')
    plt.ylabel('Number of A-Record Responses')
    plt.tight_layout()

    # Rotate x-axis labels slightly for better readability
    plt.xticks(rotation=90)

    if ecs:
        plt.title('Frequency of Country Responses independent of Source-Subnet (ECS present)')
        plt.savefig(os.path.join(plot_path,"country_amount_ecs.png"))
    else:
        plt.title('Frequency of Country Responses independent of Source-Subnet (no ECS present)')
        plt.savefig(os.path.join(plot_path,"country_amount_noecs.png"))
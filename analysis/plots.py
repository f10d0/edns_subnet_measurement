import pandas as pd
import os
import matplotlib.pyplot as plt
from ast import literal_eval
from typing import Dict

def plot_ecs_support_percentage(df: pd.DataFrame, plot_path: str):
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


def plot_returned_scopes(df: pd.DataFrame, plot_path: str):
    """
    Plot for the Distribution of Prefix lengths
    requires "scope" column and "timestamp" column for counting <- change this
    """

    if not all(k in df for k in ("scope", "timestamp")):
        print("Missing 'timestamp' or 'scope' column")
        return
    return_scopes = df.groupby("scope").count()
    return_scopes = return_scopes[["timestamp"]]

    return_scopes = return_scopes.reset_index()
    return_scopes["scope"] = return_scopes["scope"].astype(int)

    tmp_df = {"scope":[i+1 for i in range(32)], "timestamp":[0 for i in range(32)]}
    tmp_df = pd.DataFrame(data=tmp_df)

    return_scopes = pd.concat([return_scopes, tmp_df], ignore_index=True)

    return_scopes = return_scopes.groupby("scope").sum().reset_index()

    return_scopes = return_scopes.rename(columns={"timestamp": "count"})
    plot = return_scopes.plot.bar(x='scope', y='count', legend=False)
    plot.set_title("Returned scopes in ECS responses")
    plot.set_ylabel("number of responses")
    plot.get_figure().savefig(os.path.join(plot_path, "return_scopes.png"))


def plot_returned_scopes_non_24(df: pd.DataFrame, plot_path: str):
    """
    Plot for the Distribution of Prefix lengths, but this time we only take our non /24 Subnets
    requires "scope", "subnet-scope" and "timestamp" columns for counting <- change this
    """

    if not all(k in df for k in ("subnet-scope", "scope", "timestamp")):
        print("Missing 'timestamp', 'scope' or 'subnet-scope' column")
        return
    return_scopes = df[df['subnet-scope'] != 24]
    return_scopes = return_scopes.groupby("scope").count()
    return_scopes = return_scopes[["timestamp"]]

    return_scopes = return_scopes.reset_index()
    return_scopes["scope"] = return_scopes["scope"].astype(int)

    tmp_df = {"scope":[i+1 for i in range(32)], "timestamp":[0 for i in range(32)]}
    tmp_df = pd.DataFrame(data=tmp_df)

    return_scopes = pd.concat([return_scopes, tmp_df], ignore_index=True)

    return_scopes = return_scopes.groupby("scope").sum().reset_index()


    return_scopes = return_scopes.rename(columns={"timestamp": "count"})
    plot = return_scopes.plot.bar(x='scope',y='count', legend=False)
    plot.set_title("Returned scopes for subnets with non /24 prefix lengths")
    plot.set_ylabel("number of responses")
    plot.get_figure().savefig(os.path.join(plot_path, "return_scopes_non_24_input.png"))

def plot_returned_scope_comparison(df: pd.DataFrame, plot_path: str):
    """
    Plot for Prefix lengths in comparison to the input length
    requires "subnet", "scope", "subnet-scope"
    also works if "subnet" already has been split in "subnet" and "subnet-scope"
    """
    if not all(k in df for k in ("scope", "subnet", "subnet-scope")):
        print("Missing 'scope' or 'subnet' column")
        return
    scopes = df[["subnet-scope", "scope"]].dropna()
    scopes["subnet-scope"] = scopes["subnet-scope"].astype(int)
    scopes["scope"] = scopes["scope"].astype(int)
    # There must be a better way to calculate this, but this works for now
    same = len(scopes[scopes["scope"] == scopes["subnet-scope"]])
    less_specific = len(scopes[(scopes["scope"] < scopes["subnet-scope"]) & (scopes["scope"] != 0)])
    more_specific = len(scopes[scopes["scope"] > scopes["subnet-scope"]])
    zero_specific = len(scopes[scopes["scope"] == 0])
    compare_scopes = pd.DataFrame(data={"edns response scope": [same, zero_specific, less_specific, more_specific]},
                                  index=["same prefix length", "/0", "less specific prefix (none 0)", "more specific prefix"])
    plot = compare_scopes.plot.pie(y=0, legend=False, autopct='%1.1f%%')
    plot.get_figure().savefig(os.path.join(plot_path, "compare_scopes.png"))

# FIXME this is not the plot we originally wanted though i think, we need to average the averages
def plot_distance_cdf(df: pd.DataFrame, plot_path: str):
    """
    plots CDF for average-distances for domains
    only takes domains, which got distances for at least 10 different subnets in order to filter out some outliers
    requires "average-distance" and "scope" column
    """
    if not all(k in df for k in ("scope", "average-distance")):
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

def plot_continent_matches(df: pd.DataFrame, plot_path: str, ecs=True):
    """
    plots the frequency of how often the subnet used for a request matches its answer over all the domains
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
                    continue
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
        plt.title('Matches of Continent Codes per Domain (ECS present)')
        plt.savefig(os.path.join(plot_path,"continent_matches_ecs.png"))
    else:
        plt.title('Matches of Continent Codes per Domain (no ECS present)')
        plt.savefig(os.path.join(plot_path,"continent_matches_noecs.png"))

def plot_continent_distribution(df: pd.DataFrame, plot_path: str, ecs=True):
    """
    will create a plot where we count how many domains have a response in which continents (matching the original subnet's continent)
    essentially this will tell how well the domains are distributed across continents
    """

    if any(column not in df.columns for column in ["domain", "scope", "subnet-location", "ip-locations"]):
        print("Missing columns")
        return
    
    if ecs:
        df = df[df["scope"].notna()]
    else:
        df = df[df["scope"].isna()]

    continents: Dict[str, bool] = { "AF":False, "AS":False, "EU":False, "NA":False, "SA":False, "OC":False, "AN":False}
    matches: Dict[int, int]= {0:0, 1:0, 2:0, 3:0, 4:0, 5:0, 6:0, 7:0}

    for _, group in df.groupby('domain'):
        for _, row in group.iterrows():
            subnet_continent = row['subnet-location']  # Extracting the continent code of subnet-location
            subnet_continent = literal_eval(subnet_continent)[4]
            ip_locations = row['ip-locations']
            if pd.isna(ip_locations):
                continue
            ip_locations = literal_eval(ip_locations)
            for valid_ip_loc in ip_locations:
                ip_loc_continent = valid_ip_loc[4]  # Extracting the continent code of the first valid ip-location
                if ip_loc_continent:
                    if subnet_continent == ip_loc_continent:
                        continents[subnet_continent] = True
                        break
        matches[sum(cont for cont in continents.values())] += 1
        continents = {k: False for k,v in continents.items()} # reset continents matching dict

    # Plotting
    barplt = plt.bar(matches.keys(), matches.values())
    plt.xlabel('Number of Continents')
    plt.ylabel('Number of Domains')
    # Adding y-value annotations on top of each bar
    for bar, y_value in zip(barplt, matches.values()):
        plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), str(y_value),
                ha='center', va='bottom')
    if ecs:
        plt.title('Distribution of Domains per Continents (ECS present)')
        plt.savefig(os.path.join(plot_path,"continent_distribution_ecs.png"))
    else:
        plt.title('Distribution of Domains per Continents (no ECS present)')
        plt.savefig(os.path.join(plot_path,"continent_distribution_noecs.png"))

def plot_country_responses(df: pd.DataFrame, plot_path: str, ecs=True):
    """
    creates a graph of how many responses we get in total per country
    takes dataframe with domain, scope, subnet-location, ip-locations
    """

    if any(column not in df.columns for column in ["domain", "scope", "subnet-location", "ip-locations"]):
        print("Missing columns")
        return

    if ecs:
        df = df.dropna(subset=["scope","ip-locations"])
    else:
        df = df[df['scope'].isna()]
        df = df.dropna(subset=["ip-locations"])
    country_amount = {}
    
    for _, row in df.iterrows():
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
    df = df[df['Amount'] >= 50000]

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

def plot_as_distribution_graph(df: pd.DataFrame, plot_path: str):
    """
    This generates a pie chart of the distribution of AS which handles our requests that got an ECS answer
    requires "scope", "ns-as"
    """

    if not all(k in df for k in ("scope", "ns-as")):
        print("Missing 'ns-as' or 'scope' column")
        return

    ecs_df = df[df['scope'].notna()]
    ecs_df = ecs_df.groupby('ns-as').count().sort_values(ascending=False, by='scope').reset_index()

    wedges, labels, percentages = plt.pie(ecs_df['scope'], labels=ecs_df['ns-as'], autopct='%1.1f%%',
                             rotatelabels = True)
    for x in wedges[10:]:
        x.set_visible(False)
    for x in labels[10:]:
        x.set_visible(False)
    for x in percentages[3:]:
        x.set_visible(False)
    plt.figure(figsize=(10, 6))
    plt.show()
    plt.savefig(os.path.join(plot_path, "as_distribution_for_ecs_supported_servers.png"))

def plot_as_distribution_graph_non_ecs(df: pd.DataFrame, plot_path: str):
    """
        This generates a pie chart of the distribution of ASes which handles our requests that haven't got an ECS answer
        requires "scope", "ns-as"
    """

    if not all(k in df for k in ("scope", "ns-as")):
        print("Missing 'ns-as' or 'scope' column")
        return

    non_ecs_df = df[df['scope'].isna()]
    non_ecs_df['scope'] = 1
    non_ecs_df = non_ecs_df.groupby('ns-as').count().sort_values(ascending=False, by='scope').reset_index()

    wedges, labels, percentages = plt.pie(non_ecs_df['scope'], labels=non_ecs_df['ns-as'], autopct='%1.1f%%',
                                rotatelabels=True)
    for x in wedges[40:]:
        x.set_visible(False)
    for x in labels[20:]:
        x.set_visible(False)
    for x in percentages[5:]:
        x.set_visible(False)
    plt.figure(figsize=(10, 6))
    plt.show()
    plt.savefig(os.path.join(plot_path, "as_distribution_for_no_ecs_servers.png"))

def plot_non_zero_scope_answer_share(df: pd.DataFrame, plot_path: str):

    if not all(k in df for k in ("scope", "ns-as")):
        print("Missing 'ns-as' or 'scope' column")
        return

    df = df[df["scope"].notna()]
    zero_scope_df = df[df["scope"] == 0]
    with_scope_df = df[df["scope"] != 0]
    zero_scope_df = zero_scope_df.groupby("ns-as").count().reset_index()
    with_scope_df = with_scope_df.groupby("ns-as").count().reset_index()
    scope_df = zero_scope_df.merge(with_scope_df, on="ns-as", how="outer", suffixes=("-zero-count", "-non-zero-count"))
    scope_df = scope_df.fillna(0)
    scope_df["answer-count"] = scope_df["scope-non-zero-count"] + scope_df["scope-zero-count"]
    scope_df["non-zero-share"] = scope_df["scope-non-zero-count"] / scope_df["answer-count"]
    scope_df = scope_df.sort_values(by="answer-count", ascending=False)
    scope_df = scope_df.head(30)

    share_plot = scope_df.plot(x="ns-as", y="non-zero-share", kind="bar", legend=False)
    share_plot.set_title("ECS non-zero scope answer share for the 20 most frequent ASes")
    share_plot.set_ylabel("Share of ecs answer that have a non 0 scope length")
    share_plot.set_xlabel("Autonomous System")
    share_plot.get_figure().savefig(os.path.join(plot_path, "non_zero_answer_share.png"))

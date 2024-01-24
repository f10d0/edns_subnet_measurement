import pandas as pd
import os

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

    if "scope" and "timestamp" not in df.columns:
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


def plot_distance_cdf(df, plot_path):
    """
    plots CDF for average-distances for domains
    only takes domains, which got distances for at least 10 different subnets in order to filter out some outliers
    requires "average-distance" and "scope" column
    """

    if "average-distance" and "scope" not in df.columns:
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

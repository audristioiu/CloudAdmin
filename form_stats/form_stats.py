import requests
import matplotlib.pyplot as plt
import numpy as np

url = "https://localhost:9443/form_stats"

response = requests.get(url, verify=False)
data_list = response.json()

colors = {
    'total_bad_features': 'red',
    'total_good_features': 'green',
    'total_project_issues': 'blue',
    'total_project_suggestions': 'orange',
    'average_project_like_rate': 'purple',
    'average_friends_recommend_rate': 'cyan'
}



for key in data_list[0].keys():
    if key == "form_timestamp":
        continue
    unique_values = set()
    values = []
    timestamps = []
    for data in data_list:
        values.append(data[key])
        timestamps.append(data['form_timestamp'])
        if isinstance(data[key], list):
            unique_values.update(data[key])
        else:
            unique_values.add(data[key])
    if isinstance(next(iter(unique_values)), str):
        plt.figure(figsize=(10, 6))
        color_scheme = plt.cm.tab10.colors[:len(unique_values)]
        plt.bar(timestamps, len(unique_values), 0.4,label=len(unique_values))
        for idx, elem in enumerate(unique_values):
           plt.bar(idx, [1], 1, label=elem, color="white")
        plt.xlabel('Timestamp')
        plt.ylabel('Count')
        plt.title(f'Evolution of  "{key}"')
        plt.legend(loc='upper right')
        plt.yticks([1, len(unique_values)])
        plt.ylim(1, len(unique_values))
        plt.xticks(range(len(data_list)), [data['form_timestamp'] for data in data_list], rotation=45)
        plt.tight_layout()
        plt.show()
    else:
        plt.figure(figsize=(10, 6))
        plt.plot(range(len(values)), list(values), marker='o')
        plt.xlabel('Timestamp')
        plt.ylabel('Avg')
        plt.title(f'Evolution of  "{key}"')
        plt.xticks(range(len(data_list)), [data['form_timestamp'] for data in data_list], rotation=45)
        plt.ylim(1, 10)
        plt.tight_layout()
        plt.show()

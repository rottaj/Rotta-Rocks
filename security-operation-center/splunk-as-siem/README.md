# Splunk as SIEM

## Introduction

Splunk is a highly scalable, versitile data aggregation solution known for it's ability to ingest large data and visualize massive amounts of machine data.

## Splunk Architecture

Splunk Enterprise consists of several layers that work together to collect, index, search, analyze, and visualize data.

* **Forwarders**: Responsible for data collection.
  * **Universal Forwarder (UF)**: Individual, lightweight, software packages that collect data and forwards it to Splunks indexers.
  * **Heavy Forwarders (HF)**: Uses for intensive data aggreagation. Typically depoyed as dedicated nodes. They exclusively support Splunk enterprise.
* **Indexers**: Receives data from forwarders, organizes it, and stores it in indexes. Creates directories categorizes by age.
* **Search Head**s: Coordinates search jobs, dispatching them to indexers and merging results.
* **Deployment Server**: Manages configuration for forwarders, distributing apps and updates.
* **Cluster Master**: Coordinates activities of indexers in a clustered environment.
* L**icense Master**: Manages license details.

## Splunk Key Components

Apart from the overall architecture of Splunk, it can best be categorized by the following four components:

* Splunk Web Interface: Graphical User Interface in which users can interact with Splunk.
* Search Processing Language: The query language for Splunk. Allows users to search, query, and manipulate the indexed data.
* **Apps and Add-ons**: Ready made addons can be found on [Splunkbase](https://splunkbase.splunk.com/). Kind of like Burpsuite add-ons.
* Kno**wledge Objects**: Fields, tags, events, lookups, macros, data models, and alerts that enhance the data in Splunk.


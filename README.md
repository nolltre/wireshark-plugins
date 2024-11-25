# Wireshark plugins

Collection of plugins / dissectors that I've written for Wireshark

| File         | Description                                           |
| ------------ | ----------------------------------------------------- |
| `htsmsg.lua` | Dissector for the `HTSP` protocol used by [Tvheadend] |

## Installation

1. Clone this repository somewhere
1. In Wireshark:
   1. Open `Help -> About Wireshark`
   1. Open the `Folders` tab.
   1. Open your `Personal Lua Plugins` folder
   1. Create a link to the plugin / dissector you want to use

[Tvheadend]: https://tvheadend.org

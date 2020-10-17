# whois-gateway

Web-based whois gateway written in Python for lighttpd

## Deployment

* Clone this git repo into the home directory of your project
* Update `rebuild_geolocation.sh` with the download url for GeoLite2 City from your maxmind account, and run the script
* Enter a `webservice python3.7 shell`, and run `rebuild_venv.sh`
* Update `PROJECT` name in `www/python/src/app.py`, if needed
* Create a file `ipinfo_token` with your ipinfo token
* Run `webservice python3.7 start`

## API

* <code>https://tools.wmflabs.org/whois/202.12.29.175/lookup</code> or <code>/gateway.py?ip=202.12.29.175&lookup=true</code>
  * human-readable Whois result page, with a query form
* <code>https://tools.wmflabs.org/whois/202.12.29.175/lookup/json</code> or <code>/gateway.py?ip=202.12.29.175&lookup=true&format=json</code>
  * Whois result in JSON
* <code>https://tools.wmflabs.org/whois/202.12.29.175</code> or <code>/gateway.py?ip=202.12.29.175</code>
  * List of links to regional databases
* <code>https://tools.wmflabs.org/whois/202.12.29.175/redirect/NAME</code> or <code>/gateway.py?ip=202.12.29.175&provider=NAME</code>
  * Redirect to a search result page provided by NAME

## License

See [LICENSE.md](https://github.com/whym/whois-gateway/blob/master/LICENSE.md).

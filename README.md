# Toro

Toro scrapes the exit relay data from tor.org, caches it, and utilizes the data to create configuration files for blacklisting.

An integer is passed to set the date range.

Example: https://toro.threathound.com/compat/minutes/15

The above would indicate you would like all ips that were used by tor exit relays in the last 15 minutes.

In the project directory just build the application.

The server runs on port 3005 and it updates from tor.org every 5 minutes.

```$ GOOS=linux GOARCH=amd64 go build -o toro main.go```

I use caddy as a proxy in front of it for simple https.

```

toro.threathound.com {
        tls youremail@example.com
        proxy / localhost:3005 {
        }
}
```

nginx-auth
==========

Add user authentication for nginx location

Example config:
```
        location /auth {
            proxy_set_header Host $host:$server_port;
            proxy_set_header x-Forwarded-proto $scheme;
            proxy_pass http://127.0.0.1:9091;
        }

        location /srvlog {
            proxy_set_header Host $host:$server_port;
            proxy_set_header x-Forwarded-proto $scheme;
            proxy_pass http://127.0.0.1:9091;
        }
        
        location /internal-srvlog {
            proxy_set_header Host $host:$server_port;
            proxy_set_header x-Forwarded-proto $scheme;
            
            internal;
            proxy_set_header nginx_location "/internal-srvlog";
            
            proxy_pass http://127.0.0.1:9091/srvlog;
        }
```

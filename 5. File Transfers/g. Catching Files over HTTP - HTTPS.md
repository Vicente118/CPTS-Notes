### HTTP/S
Web transfer is the most common way most people transfer files because `HTTP`/`HTTPS` are the most common protocols allowed through firewalls.

### Nginx - Enabling PUT
#### Create a Directory to Handle Uploaded Files
```shell
sudo mkdir -p /var/www/uploads/SecretUploadDirectory
```
#### Change the Owner to www-data
```shell
sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory
```
#### Create Nginx Configuration File
Create the Nginx configuration file by creating the file `/etc/nginx/sites-available/upload.conf` with the contents:
```shell
server {
    listen 9001;
    
    location /SecretUploadDirectory/ {
        root    /var/www/uploads;
        dav_methods PUT;
    }
}
```

#### Symlink our Site to the sites-enabled Directory
```shell
sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/
```

#### Start Nginx
```shell
sudo systemctl restart nginx.service
```

If we get any error messages, check `/var/log/nginx/error.log`. If using Pwnbox, we will see port 80 is already in use.

If there is an error because port 80 is already bind to an nginx http server:
#### Remove NginxDefault Configuration
```shell
 sudo rm /etc/nginx/sites-enabled/default
```

Now we can test uploading by using `cURL` to send a `PUT` request. In the below example, we will upload the `/etc/passwd` file to the server and call it users.txt
#### Upload File Using cURL
```shell
curl -T /etc/passwd http://localhost:9001/SecretUploadDirectory/users.txt
```
```shell
sudo tail -1 /var/www/uploads/SecretUploadDirectory/users.txt 
```


# FFC App 

## Setup

For installing an python env the application uses Anaconda. 

For creating a new env use:

`conda env create -f conda-env.yaml `

For updating the conda env in case the requirements.txt changed

`conda env update -f conda-env.yaml --prune`

Activate the conda env:

`conda activate ffc-app`

Initialize the database:

`python init_db.py`

Start the App:

`python run.py`

# Hosting setup 
- Note: This is for my raspberry setup -> Might need adjustments if hosting on other devices
## 🐎 1. Gunicorn Setup

1. **Find your Env & Gunicorn**  
   ```bash
   conda activate ffc-app
   which gunicorn
   # e.g. /home/mabathke/miniforge3/envs/ffc-app/bin/gunicorn
   ```

2. **Create systemd Service**  
   **File:** `/etc/systemd/system/ffc-app.service`  
   ```ini
   [Unit]
   Description=Gunicorn instance to serve ffc-app
   After=network.target

   [Service]
   User=mabathke
   Group=www-data
   WorkingDirectory=/home/mabathke/ffc-app-v2
   Environment="PATH=/home/mabathke/miniforge3/envs/ffc-app/bin"
   ExecStart=/home/mabathke/miniforge3/envs/ffc-app/bin/gunicorn \
       --workers 3 \
       --bind 0.0.0.0:5000 \
       run:app

   [Install]
   WantedBy=multi-user.target
   ```

3. **Enable & Start**  
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable  ffc-app
   sudo systemctl start   ffc-app
   ```

4. **Verify**  
   - **Status:**  
     ```bash
     sudo systemctl status ffc-app
     ```
   - **Logs:**  
     ```bash
     sudo journalctl -u ffc-app -f
     ```
   - **Listen:**  
     ```bash
     ss -tlnp | grep 5000
     # should show 0.0.0.0:5000
     ```
   - **Local test:**  
     ```bash
     curl -I http://127.0.0.1:5000
     # HTTP/1.1 200 OK
     ```

---

## 🌐 2. Nginx & Let’s Encrypt

### A) Nginx Reverse-Proxy

1. **Install**  
   ```bash
   sudo apt update
   sudo apt install nginx
   ```

2. **ACME Webroot**  
   ```bash
   sudo mkdir -p /var/www/acme-challenge/.well-known/acme-challenge
   sudo chown -R www-data:www-data /var/www/acme-challenge
   ```

3. **Site config**  
   **File:** `/etc/nginx/sites-available/ffc.mywire.org`  
   ```nginx

    server {
        listen 80;
        server_name ffc.mywire.org;

        # serve ACME challenge files
        root /var/www/acme-challenge;
        location ^~ /.well-known/acme-challenge/ {
            default_type "text/plain";
            try_files $uri =404;
        }

        # everything else → HTTPS
        location / {
            return 301 https://$host$request_uri;
        }
    }

    # HTTPS ‒ terminate TLS and reverse-proxy into Gunicorn
    server {
        listen 443 ssl http2;
        server_name ffc.mywire.org;

        ssl_certificate     /etc/letsencrypt/live/ffc.mywire.org/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/ffc.mywire.org/privkey.pem;
        include             /etc/letsencrypt/options-ssl-nginx.conf;
        ssl_dhparam         /etc/letsencrypt/ssl-dhparams.pem;

        location / {
            proxy_pass         http://127.0.0.1:5000;
            proxy_set_header   Host $host;
            proxy_set_header   X-Real-IP $remote_addr;
            proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header   X-Forwarded-Proto $scheme;
        }
    }


    ```

    4. **Enable & Reload**  
    ```bash
    sudo ln -sf /etc/nginx/sites-available/ffc.mywire.org /etc/nginx/sites-enabled/
    sudo nginx -t && sudo systemctl reload nginx
   ```

### B) Certbot (Let’s Encrypt)

1. **Install**  
   ```bash
   sudo apt install certbot python3-certbot-nginx
   ```

2. **Obtain Certificate**  
   ```bash
   sudo certbot --nginx -d ffc.mywire.org
   ```
   - Enter your email  
   - Agree to TOS  
   - Choose “Redirect HTTP → HTTPS”

3. **Dry-Run Renewal**  
   ```bash
   sudo certbot renew --dry-run \
     --webroot -w /var/www/acme-challenge \
     --deploy-hook "systemctl reload nginx"
   ```

4. **Check**  
   - Renewal timer:  
     ```bash
     systemctl list-timers | grep certbot
     ```
   - Logs:  
     ```
     /var/log/letsencrypt/letsencrypt.log
     ```

---

## 🛠 3. Common Gotchas & Debugging

- **DNS**  
  ```bash
  dig +short ffc.mywire.org    # must match curl -4 ifconfig.me
  ```  
  Remove any AAAA record if you don’t use IPv6.

- **Router**  
  - Disable remote-admin on ports 80/443  
  - Forward TCP 80 → 192.168.178.54:80  
  - Forward TCP 443 → 192.168.178.54:443  

- **Firewall (Pi)**  
  ```bash
  sudo ufw allow 80,443/tcp
  sudo ufw allow 5000/tcp   # for LAN testing
  sudo ufw reload
  ```

- **IPv6**  
  - Remove AAAA in your DDNS  
  - Or disable IPv6 on Fritz!Box & Pi  
    ```bash
    # create /etc/sysctl.d/99-disable-ipv6.conf with:
    net.ipv6.conf.all.disable_ipv6 = 1
    net.ipv6.conf.default.disable_ipv6 = 1
    net.ipv6.conf.lo.disable_ipv6 = 1
    sudo sysctl --system
    sudo reboot
    ```

- **SQLite**  
  - Ensure `instance/` & `instance/site.db` exist  
  - Permissions:  
    ```bash
    sudo chown -R mabathke:www-data instance
    sudo chmod -R 775       instance
    sudo chmod 664          instance/site.db
    ```

- **DB Init**  
  ```bash
  cd scripts
  conda activate ffc-app
  python init_db.py
   ```

- **Clock Sync**  
  ```bash
  date
  sudo timedatectl set-ntp true
  ```

- **Test External Reach**  
  ```bash
  curl -I http://ffc.mywire.org/.well-known/acme-challenge/test  
  curl -4 -Iv https://ffc.mywire.org
  ```

> **Tip:** Keep this document handy—walk through each section in order to diagnose any future issues.  

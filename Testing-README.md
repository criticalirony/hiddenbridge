# Hidden Bridge Testing

Here are some notes about how the developers of Hidden Bridge have set up some of their testing

## Docker
### Install
```
sudo yum install docker-ce docker-ce-cli containerd.io
sudo systemctl enable docker
sudo systemctl start docker
```

### Query
```
sudo docker ps -a
sudo docker container list
sudo docker volume list
```

### Cleanup
```
sudo docker volume prune -f
sudo docker container prune -f
sudo docker image prune -a -f

sudo -i
docker rm $(docker ps -qa)
docker rmi -f $(docker images -qa)
docker volume rm $(docker volume ls -qf)
docker network rm $(docker network ls -q)
```

## Gitlab
```
sudo vi /etc/ssh/sshd_config

#Port 22
Port 2022

sudo systemctl restart sshd
```

```
sudo mkdir -p /srv/gitlab
export GITLAB_HOME=/srv/gitlab

sudo docker run --detach   --hostname gitlab.example.com   --publish 443:443 --publish 80:80 --publish 22:22   --name gitlab   --restart always   --volume $GITLAB_HOME/config:/etc/gitlab:Z   --volume $GITLAB_HOME/logs:/var/log/gitlab:Z   --volume $GITLAB_HOME/data:/var/opt/gitlab:Z gitlab/gitlab-ce:latest

sudo vi /srv/gitlab/config/gitlab.rb

# external_url 'GENERATED_EXTERNAL_URL'
external_url 'https://<resolveable url or ip address>'

sudo stop gitlab
sudo docker run --detach   --hostname gitlab.example.com   --publish 443:443 --publish 80:80 --publish 22:22   --name gitlab   --restart always   --volume $GITLAB_HOME/config:/etc/gitlab:Z   --volume $GITLAB_HOME/logs:/var/log/gitlab:Z   --volume $GITLAB_HOME/data:/var/opt/gitlab:Z gitlab/gitlab-ce:latest
```

## Bitbucket
```
sudo docker volume create --name bitbucketVolume
sudo docker run -v bitbucketVolume:/var/atlassian/application-data/bitbucket --name="bitbucket" -d -p 7990:7990 -p 7999:7999 atlassian/bitbucket
```

## Dumb Git (Nginx)
```
sudo mkdir -p /srv/web/sites/github /srv/web/etc
sudo docker run -it -d --rm -p 80:80 --name web -v /srv/web/sites/:/usr/share/nginx/html nginx
sudo docker cp web:/etc/nginx /srv/web/etc
sudo docker stop web

sudo vi  /srv/web/etc/nginx/conf.d/default.conf

server {
    listen       80;
    listen  [::]:80;
    serverName_  localhost;

    root   /usr/share/nginx/html;

    location / {
        autoindex on;
    }

    error_page   500 502 503 504  /50x.html;
    location = /50x.html {
        root   /usr/share/nginx/html;
    }
}

sudo docker run -it -d --rm -p 80:80 --name web -v /srv/web/sites/:/usr/share/nginx/html -v /srv/web/etc/nginx/:/etc/nginx/  nginx

sudo mkdir -p /srv/web/sites/github/golang
cd /srv/web/sites/github/golang
sudo git clone --bare https://github.com/golang/dl
cd dl
sudo git update-server-info
```

## Git Troubleshooting
### Debugging
Git has a fairly complete set of traces embedded which you can use to debug your git problems.

To turn them on, you can define the following variables:

* GIT_TRACE for general traces,
* GIT_TRACE_PACK_ACCESS for tracing of packfile access,
* GIT_TRACE_PACKET for packet-level tracing for network operations,
* GIT_TRACE_PERFORMANCE for logging the performance data,
* GIT_TRACE_SETUP for information about discovering the repository and environment it’s interacting with,
* GIT_MERGE_VERBOSITY for debugging recursive merge strategy (values: 0-5),
* GIT_CURL_VERBOSE for logging all curl messages (equivalent to curl -v),
* GIT_TRACE_SHALLOW for debugging fetching/cloning of shallow repositories.

Possible values can include:

* true, 1 or 2 to write to stderr,
* an absolute path starting with / to trace output to the specified file.
  
For more details, see: Git Internals - Environment Variables

### SSH
For SSH issues, try the following commands:
```
echo 'ssh -vvv "$*"' > ssh && chmod +x ssh
GIT_SSH="$PWD/ssh" git pull origin master
or use ssh to validate your credentials, e.g.
```

```
ssh -vvvT git@github.com
or over HTTPS port:
```

```
ssh -vvvT -p 443 git@ssh.github.com
Note: Reduce number of -v to reduce the verbosity level.
```

### Examples
```
$ GIT_TRACE=1 git status
20:11:39.565701 git.c:350               trace: built-in: git 'status'

$ GIT_TRACE_PERFORMANCE=$PWD/gc.log git gc
Counting objects: 143760, done.
...
$ head gc.log 
20:12:37.214410 trace.c:420             performance: 0.090286000 s: git command: 'git' 'pack-refs' '--all' '--prune'
20:12:37.378101 trace.c:420             performance: 0.156971000 s: git command: 'git' 'reflog' 'expire' '--all'
...

$ GIT_TRACE_PACKET=true git pull origin master
20:16:53.062183 pkt-line.c:80           packet:        fetch< 93eb028c6b2f8b1d694d1173a4ddf32b48e371ce HEAD\0multi_ack thin-pack side-band side-band-64k ofs-delta shallow no-progress include-tag multi_ack_detailed symref=HEAD:refs/heads/master agent=git/2:2.6.5~update-ref-initial-update-1494-g76b680d
```
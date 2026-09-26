# INF8602-CVE-2020-8835
## Testing the kernel exploit

1. Testing without Docker
```bash
cd ../app
npm i
node server.js
```

2. Testing with Docker to test defensive capability
```bash
# Make sure to be in the same directory as the Dockerfile
# Build the Docker image
docker build . -t inf8602/node-web-app
# Your docker image should be listed by Docker
docker images
# Run the image
docker run -p 8080:8080 -d inf8602/node-web-app
# Print the output of the app
docker ps #get the container id
docker logs <container id> # print app output
# Example
# Hello World
```

3. Testing the fix (disabling priviledge bpf)
```bash
sudo sysctl kernel.unprivileged_bpf_disabled=1
cd ../app
npm i
node server.js
```

4. Testing with Dev containers
```
Open in Container
```
### Prerequisites
- [ ] Install [Ansible](https://docs.ansible.com/ansible/latest/installation_guide/
installation_distros.html) on your local machine
    - eg: On ubuntu `sudo apt install ansible-core`
    - eg: On mac `brew install ansible`
- [ ] Install resolvelib `sudo -H pip install -Iv 'resolvelib<0.6.0'`
- [ ] Install ansible docker module `ansible-galaxy collection install community.docker`
 


## Using deploy.yaml
- This Playbook is responsible for deploying the application to a remote server.
- It will do the following things
  - Install required system packages
  - Install docker
  - Copy the promtail config file to the remote server
  - Start the promtail container
  - Start the interactsh container 

### Deploy
- export GRAFANA_CLOUD endpoint for promtail to send logs to
-  Open deploy.yaml and change the parameters in the `vars` section to match your environment/requirments.
-  Run `ansible-playbook deploy.yaml` to deploy the application.
- You can also run `ansible-playbook deploy.yaml --extra-vars "container_tag=v1.1.2"` to pass the variables from the command line.

eg:
```bash
export GRAFANA_CLOUD="https://logs-prod-us-central1.grafana.net"
ansible-playbook deploy.yaml --extra-vars "container_tag=v1.1.2"
```


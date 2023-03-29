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
  - Start the interactsh container 

### Deploy
-  Open deploy.yaml and change the parameters in the `vars` section to match your environment/requirments.
-  Run `ansible-playbook deploy.yaml` to deploy the application.
- You can also run `ansible-playbook deploy.yaml --extra-vars "container_tag=v1.1.2"` to pass the variables from the command line.
  eg:
  ```bash
  ansible-playbook deploy.yaml --extra-vars "container_tag=v1.1.2"
  ```

### Add Grafana agent
- To add grafana agent to collect node metrics and logs on you project
  Open grafan_agent.yaml update the variables as per your project and run following command
  ```
  export GRAFANA_CLOUD=****
  export PROM_URL=****
  export PROM_PASS==****
  export PROM_USERNAME==****
  ansible-playbook grafana_agent.yaml
  ```

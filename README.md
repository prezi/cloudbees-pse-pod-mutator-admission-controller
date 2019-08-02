# Mutating admission controller to fix jenkin's crap

Based on: https://github.com/morvencao/kube-mutating-webhook-tutorial

# What it does

When it's deployed if a pod has this annotation:

```yaml
cloudbees-pse-fixer.prezi.com/activate: "yes"
```

All volume mounts mounting /var/lib/jenkins will be removed from the pod. Why? Because we are installing stuff there and we only need /var/lib/jenkins/workspace to be a volume.

# Deploying

No fancy integrations yet, the jist of it is this:

```yaml

./scripts/build.sh  # build and upload image
./scripts/deploy.sh # deploy it
```

# Certificates

The admission controller depend on some certificates to be availabe
for the API to work. To regenerate that please use

```yaml

./scripts/create-signed-cert.sh
```

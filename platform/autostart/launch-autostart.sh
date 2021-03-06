#!/bin/bash
set -e -u

# interacts with keyserver

source /etc/homeworld/config/local.conf
if [ "$KIND" = master ]
then
    systemctl start  etcd etcd-metrics-exporter
    systemctl enable etcd etcd-metrics-exporter
fi
if [ "$KIND" = master ] || [ "$KIND" = worker ]
then
    systemctl start  crio crio-shutdown pull-monitor kubelet kube-proxy
    systemctl enable crio crio-shutdown pull-monitor kubelet kube-proxy
fi
if [ "$KIND" = master ]
then
    systemctl start  apiserver kube-ctrlmgr kube-scheduler
    systemctl enable apiserver kube-ctrlmgr kube-scheduler
fi
if [ "$KIND" = supervisor ]
then
    systemctl start kube-state-metrics setup-queue.timer
    systemctl enable kube-state-metrics setup-queue.timer
fi

{{/*
Expand the name of the chart.
*/}}
{{- define "guardianwaf.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "guardianwaf.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "guardianwaf.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "guardianwaf.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "guardianwaf.selectorLabels" -}}
app.kubernetes.io/name: {{ include "guardianwaf.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Service account name
*/}}
{{- define "guardianwaf.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "guardianwaf.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/* Raft membership must be configured explicitly; HPA cannot change voters. */}}
{{- define "guardianwaf.validateCluster" -}}
{{- if .Values.cluster.enabled -}}
{{- if .Values.autoscaling.enabled -}}
{{- fail "cluster mode uses fixed Raft voting membership; autoscaling must be disabled" -}}
{{- end -}}
{{- if or (lt (int .Values.cluster.replicas) 3) (eq (mod (int .Values.cluster.replicas) 2) 0) -}}
{{- fail "cluster.replicas must be an odd number of at least 3" -}}
{{- end -}}
{{- if and .Values.cluster.secret.value (lt (len .Values.cluster.secret.value) 32) -}}
{{- fail "cluster.secret.value must be at least 32 bytes" -}}
{{- end -}}
{{- end -}}
{{- end -}}

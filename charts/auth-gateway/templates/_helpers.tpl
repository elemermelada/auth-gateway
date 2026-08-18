{{/*
Base app name. Defaults to the chart name, overridable via nameOverride so the
OCI package name (Chart.Name) and the rendered resource name can differ.
*/}}
{{- define "auth-gateway.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully qualified app name, prefixed with the release name.
Truncated at 63 chars for the DNS naming spec.
*/}}
{{- define "auth-gateway.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := include "auth-gateway.name" . }}
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
{{- define "auth-gateway.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "auth-gateway.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "auth-gateway.selectorLabels" -}}
app.kubernetes.io/name: {{ include "auth-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
BACKENDS env value: the ordered "key=url" list auth-gateway routes by.

Order is button order on the selector page, and each key is the value that ends
up in a user's routing cookie — which is why the keys, not the positions, are the
identity: reordering or removing an entry never re-points an existing cookie at a
different provider. Validation mirrors the gateway's own, so a typo fails the
install instead of the pods.
*/}}
{{- define "auth-gateway.backends" -}}
{{- if not .Values.config.backends -}}
{{- fail "config.backends is required: an ordered list of {key, url, label} entries. Migrating from backendPrimary/backendSecondary? Use keys `primary` and `secondary` so existing routing cookies keep working." -}}
{{- end -}}
{{- $parts := list -}}
{{- $seen := dict -}}
{{- range .Values.config.backends -}}
{{- if not (regexMatch "^[a-z0-9_-]{1,64}$" (default "" .key)) -}}
{{- fail (printf "config.backends: key %q must match [a-z0-9_-]{1,64}" (default "" .key)) -}}
{{- end -}}
{{- if hasKey $seen .key -}}
{{- fail (printf "config.backends: key %q is listed more than once" .key) -}}
{{- end -}}
{{- $_ := set $seen .key true -}}
{{- if not (regexMatch "^https?://" (default "" .url)) -}}
{{- fail (printf "config.backends: entry %q needs a full http(s):// url (got %q)" .key (default "" .url)) -}}
{{- end -}}
{{- if or (contains "," .url) (contains "," (default "" .label)) -}}
{{- fail (printf "config.backends: entry %q must not contain a comma (the env vars are comma-separated lists)" .key) -}}
{{- end -}}
{{- $parts = append $parts (printf "%s=%s" .key .url) -}}
{{- end -}}
{{- join "," $parts -}}
{{- end }}

{{/*
BACKEND_LABELS env value: the "key=label" list for entries that set a label.
Empty when none do, so the env var is only rendered when it carries something.
*/}}
{{- define "auth-gateway.backendLabels" -}}
{{- $parts := list -}}
{{- range .Values.config.backends -}}
{{- $key := .key -}}
{{- with .label -}}
{{- $parts = append $parts (printf "%s=%s" $key .) -}}
{{- end -}}
{{- end -}}
{{- join "," $parts -}}
{{- end }}

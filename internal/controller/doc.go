// Package controller holds the operator's reconcilers. It resolves the
// provider a claim names with lib-operator-go's server.ResolveCloud, reaches it
// through the egress policy with the clients of package idpclient, keeps one
// connection per provider between reconciles (ProviderCache) and probes the
// providers' health and discovery document (Prober).
package controller

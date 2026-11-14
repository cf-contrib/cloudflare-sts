// Who gets what. The configuration, config.toml, says what each profile hands out.
//
// Every provider is admitted by a permit that pins its tenant, before any
// profile is considered: tokens from anyone else's repositories never get this far.

@id("admit-github")
permit (principal, action == Admit::Action::"github", resource)
when { context.repository_owner_id == "100000001" };

@id("admit-gitlab")
permit (principal, action == Admit::Action::"gitlab", resource)
when { context.namespace_id == "4000001" };

@id("admit-mismatched")
permit (principal, action == Admit::Action::"mismatched", resource)
when { context.namespace_id == "4000001" };

@id("admit-pinned")
permit (principal, action == Admit::Action::"pinned", resource)
when { context.namespace_id == "4000001" };

@id("admit-typed")
permit (principal, action == Admit::Action::"typed", resource)
when { context.namespace_id == "4000001" };

@id("admit-access")
permit (principal, action == Admit::Action::"access", resource)
when { context.iss == "http://127.0.0.1:8791/issuers/access" };

// Whatever the profile, a token from a fork pull request gets nothing.
@id("no-pull-request-target")
forbid (principal, action, resource)
when { context has event_name && context.event_name == "pull_request_target" };

@id("allow-example-org/infra:ci.apply")
permit (principal, action == Profile::Action::"example-org/infra:ci.apply", resource)
when { context.repository_id == "200000002" && context.ref == "refs/heads/main" && context.environment == "prod" };

@id("allow-workers-deploy")
permit (principal, action == Profile::Action::"workers-deploy", resource)
when { context.repository like "example-org/*" && context.ref == "refs/heads/main" && context.environment == "prod" };

@id("allow-misspelled")
permit (principal, action == Profile::Action::"misspelled", resource)
when { context.environment == "misspelled" };

@id("allow-lb-account")
permit (principal, action == Profile::Action::"lb-account", resource)
when { context.environment == "lb-account" };

@id("allow-lb-zone")
permit (principal, action == Profile::Action::"lb-zone", resource)
when { context.environment == "lb-zone" };

@id("allow-terraform-state")
permit (principal, action == Profile::Action::"terraform-state", resource)
when { context.repository like "example-org/state-*" && context.environment == "state" };

@id("allow-combo-deploy")
permit (principal, action == Profile::Action::"combo-deploy", resource)
when { context.environment == "combo" };

@id("allow-combo-lb")
permit (principal, action == Profile::Action::"combo-lb", resource)
when { context.environment == "combo" };

@id("allow-combo-state")
permit (principal, action == Profile::Action::"combo-state", resource)
when { context.environment == "combo" };

@id("allow-combo-state-two")
permit (principal, action == Profile::Action::"combo-state-two", resource)
when { context.environment == "combo" };

@id("allow-whole-bucket")
permit (principal, action == Profile::Action::"whole-bucket", resource)
when { context.environment == "whole-bucket" };

@id("allow-state-and-deploy")
permit (principal, action == Profile::Action::"state-and-deploy", resource)
when { context.environment == "state-and-deploy" };

@id("allow-owner-state")
permit (principal, action == Profile::Action::"owner-state", resource)
when { context.environment == "owner-state" };

@id("allow-combo-access")
permit (principal, action == Profile::Action::"combo-access", resource)
when { context.environment == "combo" };

@id("allow-combo-access-two")
permit (principal, action == Profile::Action::"combo-access-two", resource)
when { context.environment == "combo" };

@id("allow-nix-push")
permit (principal, action == Profile::Action::"nix-push", resource)
when { context.ref == "refs/heads/main" };

@id("allow-gitlab-deploy")
permit (principal, action == Profile::Action::"gitlab-deploy", resource)
when { context.project_path == "group/app" && context.ref_protected == "true" };

@id("allow-gitlab-cache")
permit (principal, action == Profile::Action::"gitlab-cache", resource)
when { context.project_path like "group/*" };

@id("allow-gitlab-state")
permit (principal, action == Profile::Action::"gitlab-state", resource)
when { context.project_path like "group/sub/*" };

@id("allow-pinned-cache")
permit (principal, action == Profile::Action::"pinned-cache", resource)
when { context.namespace_id == "4000001" };

@id("allow-example-org/app:tofu-plan")
permit (principal, action == Profile::Action::"example-org/app:tofu-plan", resource)
when { context.email == "alice@example.com" };

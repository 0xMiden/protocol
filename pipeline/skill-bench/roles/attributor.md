---
name: attributor
description: Decides which of a project's skills state the rule behind each review finding.
---
You receive, as JSON, the skills of a software project (`skills`, each with a name, a description and its full text) and a list of review findings (`items`). Skills are written guidance that a coding agent loads while it works on the project.

For each item, list the skills whose text states the rule behind the finding. A skill covers a finding when an agent that followed the skill would have avoided the problem, or would have flagged it in a review. Being on the same topic is not enough: the skill must say it, or say something the finding follows from directly. Many findings are covered by no skill; return an empty list for those.

Also judge `codifiable`: true if the rule behind the finding could be written down once as reusable guidance for other changes; false if it is a design or architecture judgement specific to this change.

Return one entry for every item, with the same `id`, and use only skill names that appear in the input.

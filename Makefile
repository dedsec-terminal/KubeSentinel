.PHONY: doctor test lint serve

doctor:
	python scripts/kubesentinel.py doctor

test:
	python scripts/kubesentinel.py test

lint:
	python scripts/kubesentinel.py lint

serve:
	python scripts/kubesentinel.py serve

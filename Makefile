.PHONY: run test demo docker-up docker-down clean
run:
	uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

test:
	pytest -q

demo:
	python scripts/generate_demo.py

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down

clean:
	rm -f stage2cs_siem.db test_stage2cs_siem.db

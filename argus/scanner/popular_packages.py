"""Static allowlists of well-known package names, bundled for offline typosquat
detection (no network calls, deterministic). Not exhaustive — a curated set of the
packages most commonly impersonated in real typosquatting incidents plus the top
of each ecosystem's popularity list.
"""

POPULAR_NPM = {
    "react", "react-dom", "react-router", "react-router-dom", "redux", "react-redux",
    "vue", "vuex", "vue-router", "angular", "next", "nuxt", "svelte", "express",
    "koa", "fastify", "nestjs", "lodash", "underscore", "axios", "request", "node-fetch",
    "moment", "dayjs", "date-fns", "chalk", "commander", "yargs", "inquirer", "typescript",
    "webpack", "vite", "rollup", "parcel", "babel", "eslint", "prettier", "jest", "mocha",
    "chai", "sinon", "cypress", "playwright", "puppeteer", "socket.io", "ws", "cors",
    "helmet", "morgan", "body-parser", "cookie-parser", "passport", "jsonwebtoken",
    "bcrypt", "bcryptjs", "dotenv", "nodemon", "pm2", "sequelize", "mongoose", "prisma",
    "knex", "pg", "mysql", "mysql2", "sqlite3", "redis", "ioredis", "graphql", "apollo-server",
    "uuid", "nanoid", "classnames", "clsx", "styled-components", "emotion", "tailwindcss",
    "postcss", "autoprefixer", "sass", "less", "core-js", "regenerator-runtime", "rxjs",
    "immer", "zustand", "recoil", "formik", "yup", "zod", "joi", "ajv", "validator",
    "async", "bluebird", "q", "rimraf", "glob", "minimatch", "semver", "chokidar",
    "fs-extra", "mkdirp", "del", "cross-env", "concurrently", "husky", "lint-staged",
    "eslint-config-prettier", "eslint-plugin-react", "eslint-plugin-import", "webpack-cli",
    "webpack-dev-server", "ts-node", "ts-loader", "babel-loader", "css-loader",
    "style-loader", "file-loader", "url-loader", "html-webpack-plugin", "mini-css-extract-plugin",
    "terser-webpack-plugin", "compression-webpack-plugin", "copy-webpack-plugin",
    "supertest", "nock", "sinon-chai", "chai-as-promised", "enzyme", "react-testing-library",
    "vitest", "tsx", "esbuild", "swc", "turbo", "lerna", "nx", "changesets",
}

POPULAR_PYPI = {
    "requests", "flask", "django", "fastapi", "numpy", "pandas", "scipy", "matplotlib",
    "scikit-learn", "tensorflow", "torch", "pytest", "sqlalchemy", "pydantic", "typer",
    "click", "rich", "httpx", "aiohttp", "boto3", "pyyaml", "jinja2", "markupsafe",
    "werkzeug", "gunicorn", "uvicorn", "celery", "redis", "psycopg2", "pymongo",
    "cryptography", "pyjwt", "bcrypt", "passlib", "python-dotenv", "setuptools", "wheel",
    "pip", "virtualenv", "tox", "black", "flake8", "mypy", "isort", "pylint", "ruff",
    "beautifulsoup4", "lxml", "scrapy", "selenium", "pillow", "opencv-python", "pytz",
    "python-dateutil", "attrs", "dataclasses-json", "marshmallow", "starlette",
    "gitpython", "docker", "kubernetes", "paramiko", "fabric", "invoke", "poetry",
    "pipenv", "twine", "build", "packaging", "wrapt", "six", "certifi", "urllib3",
    "idna", "charset-normalizer", "chardet", "colorama", "tqdm", "loguru", "structlog",
}

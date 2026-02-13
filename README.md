# sf-data-360-dlo-explorer

DLO Explorer for Salesforce Data Cloud (Data 360). It lists Data Lake Objects (DLOs), lets users select fields, and previews the first $N$ rows.

## What this delivers

1. Sorted list of all DLOs in the current Data Cloud environment
2. Input for number of records to retrieve (limit) + offset with next/prev
3. Click a DLO → render a table preview
4. Show all fields, selectable (default: all selected)

Extra user-friendly features:
- Search DLOs and fields
- Click-to-sort columns (re-runs query)
- Copy SQL + export CSV
- Simple WHERE clause (limited characters for safety)

## Files

- Backend: [server.js](server.js)
- UI: [public/index.html](public/index.html)
- Env example: [.env.example](.env.example)
- Package definition: [package.json](package.json)

## Salesforce configuration (step-by-step)

### 1) User permissions

Ensure the user has:
- Data Space access for the DLOs
- A Data Cloud permission set (for example, Data Cloud Activation Manager)

### 2) Create a Connected App / External Client App

In Salesforce Setup:
1. Create a Connected App (or External Client App, depending on your UI).
2. Enable OAuth settings.
3. Add a callback URL:
	- http://localhost:3001/auth/callback
4. Add OAuth scopes:
	- api
	- refresh_token (offline_access)
	- cdp_query_api
5. Save and copy the client id and client secret.

### 3) Allow user access to the app

If your org requires admin approval, add the user to the Connected App’s permitted profiles/permission sets.

## Local setup

1. Copy environment file:
	- from [.env.example](.env.example) to .env
2. Fill in values in .env:
	- SF_CLIENT_ID
	- SF_CLIENT_SECRET
	- SF_LOGIN_URL (login.salesforce.com or test.salesforce.com)

## Run

1. Install dependencies.
2. Start the server.
3. Open http://localhost:3001 and click Login.

## How it works

1. OAuth login against Salesforce.
2. Token exchange to Data Cloud via /services/a360/token.
3. Metadata API for DLOs and fields.
4. Query V2 API for preview rows.

## Security notes

- SQL construction is validated server-side for DLO and field identifiers.
- WHERE clause is intentionally restricted to a safe subset of characters.

## UI usage

1. Login.
2. Search and select a DLO.
3. Optionally filter fields or adjust limit/offset.
4. Click Run preview.
5. Click any column header to sort.
6. Use Copy SQL or Export CSV if needed.

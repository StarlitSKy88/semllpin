# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SmellPin is a global smell annotation platform that allows users to mark and share smell information on a map. The project uses a full-stack architecture with:

- **Frontend**: Next.js 15 with React 18 + TypeScript + Tailwind CSS
- **Backend**: Node.js + Express.js + TypeScript  
- **Workers**: Cloudflare Workers with Hono framework
- **Database**: PostgreSQL with PostGIS (production uses Neon PostgreSQL, NOT Supabase)
- **Cache**: Redis for session storage and caching
- **Payments**: Stripe integration for annotation fees

## Architecture

The project follows a microservices architecture:

```
├── frontend/          # Next.js frontend application
├── workers/           # Cloudflare Workers API
├── src/              # Backend Node.js API
├── migrations/       # Database migrations
├── seeds/            # Database seed data
└── docs/            # Project documentation
```

## Development Commands

### Root Project
- `npm run dev` - Start backend development server (port 3000)
- `npm run build` - Build the backend
- `npm test` - Run all tests (frontend + backend)
- `npm run lint` - Run ESLint on backend code
- `npm run migrate` - Run database migrations
- `npm run seed` - Seed database with test data

### Frontend (Next.js)
```bash
cd frontend
npm run dev        # Start development server (port varies)
npm run build      # Build for production
npm run start      # Start production server
npm run lint       # Run Next.js linting
```

### Workers (Cloudflare)
```bash
cd workers
npm run dev                # Start local development
npm run deploy             # Deploy to production
npm run deploy:staging     # Deploy to staging
npm run build             # Dry-run build
npm run test              # Run tests with Vitest
```

## Database Configuration

**IMPORTANT**: The project MUST use Neon PostgreSQL as the production database. Supabase is strictly prohibited per project rules.

- Development: Uses SQLite for local development
- Production: Neon PostgreSQL with PostGIS extension
- Migrations: Use Knex.js migration system

## Key Technical Constraints

1. **Database**: Must use Neon PostgreSQL (never Supabase)
2. **Maps**: Uses OpenStreetMap + Mapbox (no Google Maps dependency)
3. **TypeScript**: Strict mode enabled across all components
4. **Architecture**: Microservices with separate frontend, workers, and backend
5. **Payment**: Stripe integration for annotation fees
6. **Geographic**: PostGIS extension required for location queries
7. **Authentication**: JWT-based authentication system

## Testing

- Backend: Jest with separate configs for frontend/backend
- Workers: Vitest for unit testing
- Integration: Comprehensive test suite with database validation
- E2E: Custom end-to-end integration tests

Test commands:
- `npm run test:frontend` - Frontend tests
- `npm run test:backend` - Backend tests  
- `npm run test:database` - Database validation
- `npm run test:comprehensive` - Full test suite

## Environment Variables

Key environment variables needed:
- `DATABASE_URL` - PostgreSQL connection string
- `JWT_SECRET` - JWT signing secret
- `STRIPE_SECRET_KEY` - Stripe API key
- `NEXT_PUBLIC_MAPBOX_ACCESS_TOKEN` - Mapbox access token (optional)
- `NEXT_PUBLIC_OSM_TILE_URL` - OpenStreetMap tile server URL
- `NEXT_PUBLIC_NOMINATIM_URL` - Nominatim geocoding service URL
- `PAYPAL_CLIENT_ID` / `PAYPAL_CLIENT_SECRET` - PayPal integration

## Deployment

- **Frontend**: Vercel deployment
- **Workers**: Cloudflare Workers with `wrangler deploy`
- **Backend**: Traditional Node.js deployment
- **Database**: Neon PostgreSQL (production)

## Code Style

- ESLint + Prettier for consistent formatting
- TypeScript strict mode
- Component naming: PascalCase
- Function naming: camelCase
- File naming: kebab-case

## Key Business Logic

1. **Annotation System**: Users create paid smell annotations on the map
2. **LBS Rewards**: Location-based rewards when users discover annotations
3. **Payment Flow**: Stripe handles annotation fees with platform commission
4. **Geographic Queries**: PostGIS for location-based searches
5. **Real-time**: Socket.io for live updates

## Development Guidelines

- Always check database connection before operations
- Use TypeScript strict types throughout
- Follow existing patterns for API routes and database models  
- Test both unit and integration scenarios
- Maintain backward compatibility with existing APIs
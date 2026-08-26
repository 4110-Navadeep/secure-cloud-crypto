# Use official light Node.js environment
FROM node:18-alpine

# Create app directory
WORKDIR /usr/src/app

# Install app dependencies
COPY package*.json ./
RUN npm ci --only=production

# Bundle app source
COPY . .

# Expose port (Render sets PORT env)
EXPOSE 5000

# Start server
CMD [ "npm", "start" ]

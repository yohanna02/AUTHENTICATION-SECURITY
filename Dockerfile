FROM node:18

WORKDIR /app

COPY package.json .

RUN npm install

COPY . .

RUN cp views ./dist/ -r
RUN cp public ./dist/ -r

EXPOSE 3000

RUN npx prisma generate

RUN npm run build

CMD ["npm", "start"]
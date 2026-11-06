# --- Dependency Stage ---

FROM node:12-alpine

ENV WORKDIR /usr/src/app/

WORKDIR $WORKDIR

COPY package*.json $WORKDIR

RUN npm install --production --no-cache


# --- Runtime Stage --

FROM node:12-alpine

ENV PORT=4043
ENV MONGODB_URI=mongodb://mongo30:27017/nodegoat
ENV USER node
ENV WORKDIR /home/$USER/app

WORKDIR $WORKDIR

COPY --from=0 /usr/src/app/node_modules node_modules

RUN chown $USER:$USER $WORKDIR

COPY --chown=node . $WORKDIR

# In production environment uncomment the next line
# Then all further actions including running the containers should be done under non-root user.
RUN chown -R $USER:$USER /home/$USER && chmod -R g-s,o-rx /home/$USER && chmod -R o-wrx $WORKDIR

USER $USER

EXPOSE $PORT

CMD ["npm", "start"]
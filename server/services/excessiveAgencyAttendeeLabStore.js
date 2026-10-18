function attendeeKey(platformUserId) {
  return String(platformUserId);
}

function createExcessiveAgencyAttendeeLabStore({
  createDatabase = require('../database/excessiveAgencyLabDb').createExcessiveAgencyLabDb,
  createToolRouter = require('./excessiveAgencyToolRouter').createExcessiveAgencyToolRouter,
} = {}) {
  const attendees = new Map();
  const sessions = new Map();

  function getOrCreate(platformUserId) {
    const key = attendeeKey(platformUserId);
    if (!attendees.has(key)) {
      const database = createDatabase();
      attendees.set(key, {
        platformUserId: key,
        database,
        toolRouter: createToolRouter(database),
        conversations: new Map(),
      });
    }
    return attendees.get(key);
  }

  return {
    getOrCreate,

    createSession(token, platformUserId, labUser) {
      const key = attendeeKey(platformUserId);
      const state = getOrCreate(key);
      sessions.set(token, { platformUserId: key, labUser, state });
      return sessions.get(token);
    },

    resolveSession(token, platformUserId) {
      const session = sessions.get(token);
      if (!session || session.platformUserId !== attendeeKey(platformUserId)) return null;
      return session;
    },

    deleteSession(token) {
      sessions.delete(token);
    },

    resetAttendee(platformUserId) {
      const state = getOrCreate(platformUserId);
      state.database.reset();
      state.conversations.clear();
      return state;
    },

    resetAll() {
      attendees.clear();
      sessions.clear();
    },

    resetAllProgress() {
      for (const state of attendees.values()) {
        state.database.resetAllUserProgress();
      }
    },

    get activeSessionCount() {
      return sessions.size;
    },

    get attendeeCount() {
      return attendees.size;
    },
  };
}

function createPostgresExcessiveAgencyAttendeeLabStore({
  manager = require('../database/postgres/excessiveAgencyLabDb'),
  createToolRouter = require('./excessiveAgencyToolRouter').createExcessiveAgencyToolRouter,
} = {}) {
  const attendees = new Map();
  const initializing = new Map();
  const deleting = new Set();
  let bulkReset = null;
  const resetting = () => Object.assign(new Error('Lab reset is in progress'), { code: 'LAB_RESET_PENDING' });
  const unavailable = () => Object.assign(new Error('Attendee is being deleted'), { code: 'ATTENDEE_DELETED' });
  async function getOrCreate(platformUserId) {
    const key = attendeeKey(platformUserId);
    if (bulkReset) throw resetting();
    if (deleting.has(key)) throw unavailable();
    if (attendees.has(key)) return attendees.get(key);
    if (!initializing.has(key)) {
      const pending = (async () => {
        const database = await manager.forAttendee(key);
        await database.ensureSeeded();
        if (bulkReset) throw resetting();
        if (deleting.has(key)) throw unavailable();
        const state = { platformUserId:key,database,toolRouter:createToolRouter(database),conversations:database.conversations };
        attendees.set(key,state);
        return state;
      })();
      initializing.set(key,pending);
    }
    const pending = initializing.get(key);
    try { return await pending; }
    finally { if (initializing.get(key) === pending) initializing.delete(key); }
  }
  return {
    getOrCreate,
    async createSession(token,platformUserId,labUser){const state=await getOrCreate(platformUserId);await state.database.createSession(token,labUser.userId);return{platformUserId:attendeeKey(platformUserId),labUser,state};},
    async resolveSession(token,platformUserId){
      const key = attendeeKey(platformUserId);
      if (bulkReset || deleting.has(key)) return null;
      const database = attendees.get(key)?.database || await manager.forAttendee(key);
      const session = await database.resolveSession(token);
      if (!session || bulkReset || deleting.has(key)) return null;
      const state = await getOrCreate(key);
      return {...session,state};
    },
    async deleteSession(token,platformUserId){
      const key = attendeeKey(platformUserId);
      const database = attendees.get(key)?.database || await manager.forAttendee(key);
      await database.deleteSession(token);
    },
    async resetAttendee(platformUserId){const state=await getOrCreate(platformUserId);await state.database.reset();return state;},
    async destroyAttendee(platformUserId) {
      const key = attendeeKey(platformUserId);
      deleting.add(key);
      try { await initializing.get(key); } catch { /* Still remove partially seeded rows. */ }
      attendees.delete(key);
      return manager.destroyAttendee(key);
    },
    async resetAll(){
      if (!bulkReset) {
        bulkReset = Promise.resolve().then(async () => {
          await Promise.allSettled([...initializing.values()]);
          attendees.clear();
          await manager.resetAll();
        });
      }
      const current = bulkReset;
      try { await current; }
      finally { if (bulkReset === current) bulkReset = null; }
    },
    async resetAllProgress(){await manager.resetAllProgress();},
    async getActiveSessionCount(){return manager.activeSessionCount();},
    get attendeeCount(){return attendees.size;},
  };
}

const excessiveAgencyAttendeeLabStore = process.env.PLATFORM_DATABASE_ENGINE === 'postgres'
  ? createPostgresExcessiveAgencyAttendeeLabStore()
  : createExcessiveAgencyAttendeeLabStore();

module.exports = {
  createExcessiveAgencyAttendeeLabStore,
  createPostgresExcessiveAgencyAttendeeLabStore,
  excessiveAgencyAttendeeLabStore,
};

'use strict';
const { withTransaction } = require('./index');
function createSecureShopAccountRepository(pool) {
  const one = async (sql, params) => (await pool.query(sql, params)).rows[0];
  return {
    findById: id => one('SELECT * FROM secureshop.shop_users WHERE id=$1', [id]),
    findByUsername: username => one('SELECT * FROM secureshop.shop_users WHERE username=$1', [username]),
    findConflict: (username,email) => one('SELECT id FROM secureshop.shop_users WHERE username=$1 OR email=$2', [username,email]),
    createUser: (username,email,password,role,fullName) => one('INSERT INTO secureshop.shop_users(username,email,password,role,full_name) VALUES($1,$2,$3,$4,$5) RETURNING *', [username,email,password,role,fullName]),
    findCompanion: (canonical,legacy,role) => one('SELECT * FROM secureshop.shop_users WHERE username IN($1,$2) AND role=$3 ORDER BY (username=$1) DESC LIMIT 1', [canonical,legacy,role]),
    recordLogin: (owner,ip,userAgent) => pool.query('INSERT INTO secureshop.user_sessions(user_id,ip,user_agent,last_seen_at) VALUES($1,$2,$3,CURRENT_TIMESTAMP)', [owner,ip,userAgent]),
    recordLogout: owner => pool.query('UPDATE secureshop.user_sessions SET revoked_at=CURRENT_TIMESTAMP WHERE id=(SELECT id FROM secureshop.user_sessions WHERE user_id=$1 AND revoked_at IS NULL ORDER BY last_seen_at DESC,id DESC LIMIT 1)', [owner]),
    updateProfile: (owner,name,email,phone) => one('UPDATE secureshop.shop_users SET full_name=$2,email=$3,phone=$4,updated_at=CURRENT_TIMESTAMP WHERE id=$1 RETURNING *', [owner,name,email,phone]),
    changePassword: (owner,oldHash,newHash) => pool.query('UPDATE secureshop.shop_users SET password=$3,updated_at=CURRENT_TIMESTAMP WHERE id=$1 AND password=$2', [owner,oldHash,newHash]),
    listAddresses: async owner => (await pool.query('SELECT id,label,line1,line2,city,state,zip,phone,is_default,created_at FROM secureshop.user_addresses WHERE user_id=$1 ORDER BY is_default DESC,id ASC', [owner])).rows,
    async saveAddress(owner,id,fields) {
      return withTransaction(pool,async client => {
        // Serialize default-address changes per account; never clear the default
        // until the requested owned address is known to exist.
        const user=await client.query('SELECT id FROM secureshop.shop_users WHERE id=$1 FOR UPDATE',[owner]);
        if(!user.rowCount)return null;
        if(id!=null&&!(await client.query('SELECT id FROM secureshop.user_addresses WHERE id=$1 AND user_id=$2',[id,owner])).rowCount)return null;
        if(fields[7])await client.query('UPDATE secureshop.user_addresses SET is_default=0 WHERE user_id=$1',[owner]);
        if(id==null)return(await client.query('INSERT INTO secureshop.user_addresses(user_id,label,line1,line2,city,state,zip,phone,is_default) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id',[owner,...fields])).rows[0];
        return(await client.query('UPDATE secureshop.user_addresses SET label=$3,line1=$4,line2=$5,city=$6,state=$7,zip=$8,phone=$9,is_default=$10 WHERE id=$1 AND user_id=$2 RETURNING id',[id,owner,...fields])).rows[0];
      });
    },
    deleteAddress: (owner,id) => pool.query('DELETE FROM secureshop.user_addresses WHERE id=$1 AND user_id=$2',[id,owner]),
    rotateKey: (owner,key) => pool.query('UPDATE secureshop.shop_users SET api_key=$2 WHERE id=$1',[owner,key]),
    listSessions: async owner => (await pool.query('SELECT id,ip,user_agent,created_at,last_seen_at,revoked_at FROM secureshop.user_sessions WHERE user_id=$1 AND revoked_at IS NULL ORDER BY last_seen_at DESC,id DESC LIMIT 20',[owner])).rows,
    revokeSession: (owner,id) => pool.query('UPDATE secureshop.user_sessions SET revoked_at=CURRENT_TIMESTAMP WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL',[id,owner]),
  };
}
module.exports={createSecureShopAccountRepository};

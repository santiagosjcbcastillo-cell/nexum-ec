const { admin, db, auth } = require('../lib/firebase-admin');


module.exports = async function handler(req,res){

    if(req.method !== 'GET'){
        return res.status(405).json({
            error:'Método no permitido'
        });
    }


    try{


        const authorization =
            req.headers.authorization || '';


        if(!authorization.startsWith('Bearer ')){
            return res.status(401).json({
                error:'No autenticado'
            });
        }


        const token =
            authorization.substring(7);


        const decoded =
            await auth.verifyIdToken(token);


        const uid = decoded.uid;



        const userDoc =
            await db.collection('users')
            .doc(uid)
            .get();


        if(!userDoc.exists){
            return res.status(403).json({
                error:'Usuario inválido'
            });
        }


        const user =
            userDoc.data();



        // Solo SuperAdmin

        if(user.role !== 1){
            return res.status(403).json({
                error:'Sin permisos'
            });
        }



        const logsSnap =
            await db.collection('securityLogs')
            .orderBy('timestamp','desc')
            .limit(200)
            .get();



        const logs =
            logsSnap.docs.map(doc=>({

                id:doc.id,

                ...doc.data(),

                timestamp:
                    doc.data().timestamp
                    ?.toDate()
                    ?.toISOString() || null

            }));



        return res.status(200).json({
            logs
        });



    }catch(error){

        console.error(
            'Get security logs:',
            error
        );


        return res.status(500).json({
            error:'No fue posible consultar auditoría'
        });

    }

};

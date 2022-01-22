import config from 'config';
import { dbConfig } from '@interfaces/db.interface';

const { host, port, database }: dbConfig = config.get('dbConfig');

export const dbConnection = {
  url: `mongodb+srv://JwtUsername:JwtPassword@cluster0.0nfbu.mongodb.net/myFirstDatabase?retryWrites=true&w=majority`,
  options: {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useFindAndModify: false,
  },
};
//url: `mongodb+srv://JwtUsername:JwtPassword@cluster0.0nfbu.mongodb.net/myFirstDatabase?retryWrites=true&w=majority`
//url: `mongodb://${host}:${port}/${database}`
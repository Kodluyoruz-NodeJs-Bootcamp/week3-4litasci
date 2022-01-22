import logo from './logo.svg';
import './App.css';
import { BrowserRouter as Router,Routes,Route } from "react-router-dom";
import axios from "axios";
import React from "react";
import { TextField,Button } from '@mui/material';
import List from "./components/list.component";
import Login from "./components/login.component";
import Register from "./components/register.component";



function App() {

  
  return (
    <Router >
    <Routes>
    <Route path="/" element={<List />} />
     <Route path="/list" element={<List />} />
     <Route path="/login" element={<Login />} />
     <Route path="/register" element={<Register />} />
     </Routes>
    </Router>
  );
}

export default App;

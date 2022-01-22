import React, { Component } from "react";
import axios from "axios";

import { TextField, Button, Stack, Divider, Container } from "@mui/material";

const baseURL = "http://localhost:3002";
export default class Login extends Component {
  constructor(props) {
    super(props);
    this.onLogin = this.onLogin.bind(this);
    this.state = {
      email: "",
      password: "",
      resultvalue: "",
    };
  }


  handleEmail = (event) => {
    this.setState({
      email: event.target.value,
      resultvalue: "",
    });
  };
  handlePassword = (event) => {
    this.setState({
      password: event.target.value,
      resultvalue: "",
    });
  };

  onLogin() {
    const userJson = {
      email: this.state.email,
      password: this.state.password,
    };
    axios
      .post(`${baseURL}/login`, userJson, {
        headers: {
          "Content-type": "application/json; charset=UTF-8",
        },
      })
      .then((json) => {
        console.log(json.data.token);
        localStorage.setItem('verySecureJWT', json.data.token);
        window.location = "/list";
      })
      .catch((err) => {
        console.log(err);
        this.changeResult(err.response.data);
      });
  }

  changeResult = (resultText) => {
    this.setState({ resultvalue: resultText });
  };
  render() {
    return (
      <div>
        <div className="App">
          <Container maxWidth="sm">
            <Stack spacing={2}>
              <h3>Login</h3>
              <TextField
                id="inputemail"
                label="Email"
                variant="outlined"
                value={this.state.email}
                onChange={this.handleEmail}
              />
              <TextField
                id="inputpassword"
                label="Password"
                type="password"
                variant="outlined"
                value={this.state.password}
                onChange={this.handlePassword}
              />
              <Button variant="contained" onClick={this.onLogin}>
                Login
              </Button>
              <div> {this.state.resultvalue}</div>
            </Stack>
          </Container>
        </div>
      </div>
    );
  }
}

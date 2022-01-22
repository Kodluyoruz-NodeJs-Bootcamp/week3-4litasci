import React, { Component } from "react";
import axios from "axios";

import { TextField, Button, Stack, Divider, Container } from "@mui/material";

const baseURL = "http://localhost:3002";
export default class Register extends Component {
  constructor(props) {
    super(props);
    this.onRegister = this.onRegister.bind(this);
    this.state = {
      fullname: "",
      email: "",
      password: "",
      resultvalue: "",
    };
  }

  handleFullname = (event) => {
    this.setState({
      fullname: event.target.value,
      resultvalue: "",
    });
  };
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

  onRegister() {
    const userJson = {
      fullname: this.state.fullname,
      email: this.state.email,
      password: this.state.password,
    };
    axios
      .post(`${baseURL}/register`, userJson, {
        headers: {
          "Content-type": "application/json; charset=UTF-8",
        },
      })
      .then((json) => {
        console.log(json);

        window.location = "/login";
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
              <h3>Register</h3>
              <TextField
                id="inputfullname"
                label="Full Name"
                variant="outlined"
                value={this.state.fullname}
                onChange={this.handleFullname}
              />
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
              <Button variant="contained" onClick={this.onRegister}>
                register
              </Button>
              <div> {this.state.resultvalue}</div>
            </Stack>
          </Container>
        </div>
      </div>
    );
  }
}
